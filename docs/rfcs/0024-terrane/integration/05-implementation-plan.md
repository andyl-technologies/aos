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

**Status:** In progress; eight of twenty-two T1 tasks are complete.
The combined read candidate `be832963c4` failed strict native all-target
Clippy on two large enum variants. The reviewed enum, PACK-16 attribution,
native fixture, producer-history and GC handoff corrections are composed on
`f0d494fb01`. Its public SDK fixture's disallowed randomized `HashMap` is
corrected with full-identity ordered storage. The generic closing-pause fixture
now uses its actual content observer. After removing the unused test accessor,
frozen candidate `05b1e3916e` passes strict native all-target Clippy with
warnings denied. Its original test compilation and fresh executable-bound
inventory pass. The selected twenty-nine native cases finish with twenty-six
passes, two failures and one timeout at the unchanged deadlines (190.181
seconds; run `804a89f5-c11d-4aec-adf8-7be70d3bba6e`,
`/tmp/terrane-t1-read-05b1e391-qualification/read-runtime.log`). The failures
expose colliding hardlink fixture names and an absent prior-range comparison;
the dictionary dependency case times out at 120.004 seconds. Public SDK and
dependent qualification remain unrun. The candidate's registry Nix gate
passes all 292 mappings and 69 current plan citations.
Nine isolated implementation worklines cover chunking/codecs, contextual
algebra, pure properties, native provenance disclosure, domains, native cold
forks, contextual indexes, nested overlay materialization and held content reads
with disjoint file ownership. The codec correction
passes ten focused tests and strict native all-target Clippy; its owning Nix
gates remain pending. Corrected read candidate `f87a19175a` passes fresh strict
native all-target Clippy, fresh test compilation and executable-bound inventory
after removing an unused shared registration. Its mandatory twenty-nine-case
run is terminal with twenty-eight passes and one dictionary-case timeout at
the unchanged 120-second limit (181.272 seconds;
run `b1714418-7bf1-4194-a449-cb6f83123793`). Both earlier failures now pass.
A separate diagnostic identifies a fixture-held duplicate namespace lock
surviving publication and blocking the reopened public read. Candidate
`5a284a967c` releases that fixture adapter after the real publication ACK and
before reopening. Fresh strict Clippy, compilation and executable-bound
inventory pass. The mandatory twenty-nine cases all pass in 32.162 seconds
at their unchanged deadlines, and the exact public SDK case passes in 0.009
seconds. All source and bound executable seals remain unchanged. The separate
ninety-three-case read qualification finishes with ninety-two passes and one
backfill timeout at 120.043 seconds (310.037 seconds overall;
run `8c7e618d-f331-492a-a90a-7ef74225d49e`). All seventeen ordinary-read and
namespace cases pass. A focused diagnostic reaches post-backfill current
lookup; repeated held content reads replay the selected publication history.
A separate implementation workline reuses the existing request-local retained
read closure while preserving fresh authority and physical closing checks.
Its source candidate `711c79bf7b` adds seven native/scalar witnesses for bounded
reads, physical replacement, dictionaries, selected-state changes, supported
errors and cancellation. The nested materializer candidate `46d7dfda3a` adds
twenty-four pure witnesses and the D-116 structural correction; its public
policy value retains independently resolved boundary properties without
granting authority. Their exact selectors are registered in the owning GET
and algebra gates. Scoped formatting and whitespace checks pass; compilation
and runtime qualification remain pending. Native deletion candidate
`26dc8998b0` passes its required native build and strict all-target Clippy;
its test compilation and exact 983-case inventory pass. The three native
deletion cases pass in 124.015 seconds overall and the two native domain
storage cases pass in 5.070 seconds, using the default profile, one test worker
and no phase tracing. Source, inventory and all three executable seals remain
unchanged. The held-read candidate `45dbc23e3c` now includes the reviewed
materializer prerequisite and owning gate registrations. Its native build and
actual all-target test compilation pass; strict Clippy refuses the imported
materializer's complex private property type. The reviewed named alias resolves
that source issue. Candidate `b57d9af689` preserves all seven held selectors
while adding actual read-only, legacy refusal, member-body coverage and existing
lock continuity assertions. Its native build passes; strict Clippy detects the
same fixture source included twice. A parent-owned test-only visibility change
allows reuse of the original fixture without copying it or suppressing the lint;
candidate `019e904fc7` passes its native build and strict all-target Clippy;
actual test compilation and executable-bound inventory pass. Its seven held
cases finish with three passes and four `Unsupported` failures in 12.001
seconds at the unchanged deadlines. The initial observed-only selection lacks
the retained physical recipes required by the closing ledger. A reviewed
read-only retained-selection helper supports both actual held roles, preserves
strict protected receipts and fresh selected checks, and performs no repair.
Physical fault assertions now require corruption or unavailability so generic
unsupported refusal cannot qualify original-input closing. Corrected retained-read
candidate
`c6d5227e81` passes its required native build and strict all-target Clippy;
actual all-target test compilation and executable-bound inventory pass. Its
seven held-read witnesses all pass in 16.499 seconds at the unchanged default
deadlines, with source and executable seals unchanged (run
`c2611fb8-11a8-4ba5-be63-df8db2974764`). The separate twenty-four pure overlay
cases on that frozen candidate finish with seven passes and seventeen failures.
The unset baseline's internal encoding is incorrectly validated as an explicit
property binding, and a virtual range starting after a punctuation sibling
omits crossing graft children. Both corrections remain in the isolated
materializer workline; no negative refusal or earlier source review qualifies
these failures. Corrected materializer `f7bb875512` passes its native core build,
actual test compilation and executable-bound inventory. All twenty-four exact
overlay cases now pass in 0.163 seconds at the unchanged default deadlines
(run `43c84b66-1e20-4608-9cd2-87e9c0a6cc1e`), including independent nested
policy contexts and punctuation-range output. Source and executable seals
remain unchanged. Strict all-target Clippy fails on the fixture's constant
`chunks_exact` loop. Corrected candidate `f9d2f4953b` preserves the exact pair
assertions and passes actual test compilation and executable-bound inventory;
strict Clippy then reports eight existing test-only `unwrap`/`expect` findings
in the active publication-policy and selected-property fixtures. The reviewed
parent prerequisite replaces those calls with explicit diagnostic panics,
preserving their populations and assertions without lint suppression or
production changes. Its import waits for the frozen candidate's runtime
commands to finish. After its shared Cargo lock wait, the original exact
overlay run passes all twenty-four cases in 0.149 seconds with no skipped
tests (run `225dce5b-cab4-4707-9ac8-d2bf5fc01ba0`). All tracked source and
six bound executable seals remain unchanged before and after execution.
The complete 534-case core run on that same frozen candidate finishes with
532 passes, two failures and no skipped tests in 6.583 seconds (run
`5fa17a00-ae2c-4f51-8bd2-0a1b8ac533da`). Source and all executable seals
remain unchanged. The failures are the older global-registry witness, which
calls registered property revision three unsupported without its required
35-name vocabulary, and the selected-property witness, which expects a schema
error where canonical CBOR validation returns its precise unsupported-value
error. The composed recorded-semantics implementation already distinguishes
the registered vocabulary mismatch from an unknown revision; an additional
isolated witness independently frames the complete revision-three registry.
The selected-property correction retains exact errors for all three inputs.
The older candidate's full suite remains red. The materializer imports
only the reviewed lint prerequisite after every frozen process finishes;
candidate `e1cf7ac1a3` passes strict all-target Clippy, actual test compilation,
genuine Cargo and binary metadata generation, and executable-bound inventory.
Its exact twenty-four overlay cases pass in 0.127 seconds using the official
reused-build metadata at unchanged limits; the other 510 cases are outside
that selector, with no selected case skipped. Its full 534-case run again
has 532 passes and the same two failures, with no skips, in 6.622 seconds
(run `c533c3d8-ac28-4143-a7db-9b97a3518e56`). All source, executable and
metadata seals remain unchanged. No older partial result qualifies the newer
composed recorded-semantics candidate.
Fresh assembled candidate `999de08657` fails its actual native library build
with two `E0509` errors in qualified owner-metadata traversal: `EntryKind` has
an iterative destructor, so its property and conflict fields cannot be moved
out. All 6,209 tracked source entries remain unchanged; dependent checks do
not run. Reviewed correction `ca655eb987` borrows the decoded entries and
conflict sides, copies target digests and clones only retained graft overrides.
It preserves traversal order and metadata-only accounting without cloning
recursive graphs. Corrected native compilation remains pending while the
independent core qualification proceeds on its frozen candidate.
That frozen assembled core candidate passes its library build, strict
all-target Clippy, actual all-target test compilation and genuine executable-bound
inventory. The independent current-registry witness passes. Its complete
752-case population finishes with 750 passes, two failures and no skips in
19.330 seconds at the unchanged default limits. The failures are completion
arena accounting after a second successful layer completion, and a source
discovery fixture's expected overlay-layer refusal. Separate task worktrees
investigate both against the contextual layer contract; no assertion is weakened
to qualify the failures. All 6,209 tracked source entries and eleven compiled
executable seals remain unchanged. Nine executable suites contain the 752
nonignored tests; the two additional all-target examples are explicitly
non-test targets and remain sealed separately. Corrected native qualification
proceeds independently; the complete core run and owning gates remain required.
Reviewed correction `09f75e0635` retains the exact 88-byte refusal-fixture
checkpoint and independently checks the accepted layer's additional 87-byte
binding, its work counter and unchanged source bytes. Correction `0284c205a9`
checks actual layer file populations and repeated grafts against the exhaustive
oracle, whiteout/file transitions and separate discovery accounting; ordinary
whiteout contexts still return the exact tree error. Its public documentation
correction changes no production behavior. Fresh corrected native candidate
`59a18efc11` passes the library build, then fails actual all-target checking on
three disclosure-fixture compiler errors. Correction `56e3ce3e77` checks exact
protected Original identities and reopens the independent private source through
the existing production metadata factory. Both frozen source packets remain
unchanged. The reviewed corrections are composed as `9eb308e352`; fresh native
qualification and the hermetic `core-fuzz` gate run independently, using separate
Cargo targets. Full current core execution remains pending.
Frozen `9eb308e352` now passes strict all-target core Clippy, actual all-target
test compilation and genuine executable-bound inventory. Both corrected exact
cases pass; its complete 752-case core population passes with no failures or
skips in 20.249 seconds at the unchanged default limits. All tracked source and
eleven executable seals remain unchanged. The actual hermetic `core-fuzz` gate
also passes its exact 59-case integration inventory and execution plus all five
required unit properties, with the filtered Nix source independently bound to
the frozen checkout. Native all-target checking on that candidate exposes one
remaining teardown type mismatch. Reviewed correction `0e5dfaa618` consumes
the genuine production source before deleting its protected controls, storage
and credentials; exact physical absence and destination-only reopen assertions
remain required. Corrected composition `7d7f050095` proceeds to fresh native
qualification and the independent hermetic `golden-vectors` gate. These earlier
core results do not replace qualification of the final aggregate source.
Native candidate `7d7f050095` passes its library build and then fails strict
all-target checking on five test-only `unwrap`/`expect` lints. Reviewed
correction `fa83a94182` propagates the canonical occurrence witness's errors
and preserves exact protected Original identity assertions with explicit
diagnostic panics. It adds no suppression and changes no production behavior
or assertion. Corrected composition `66c861a2b6` proceeds to fresh native
qualification while the independent golden-vector check continues on its
unchanged frozen candidate. No dependent native runtime is claimed from the
failed all-target check.
Frozen `66c861a2b6` now passes its required native library build, strict
all-target Clippy and actual all-target test compilation. All 6,209 tracked
source entries remain unchanged. Fresh genuine metadata and executable-bound
inventory discover 1,002 tests across three suites. Its first unchanged,
untraced backfill witness times out after 120.004 seconds, with no typed error
returned before termination. Source and selected executable seals remain
unchanged. The dependent ninety-three-case population, mandatory native read
cases and SDK case do not run; these compiler results do not establish runtime
success. Independent reviews examine preparation and normal publication without
relaxing deadlines or authority. The required application test-target
build proceeds independently on `4a1ff5d5fb`, using ordinary hermetic derivations
with shared caches disabled. Its configured Linux scope includes all twenty-nine
packages and all five Terrane crates. Golden-vector consumers continue on their
own frozen source; the complete aggregate remains pending.
Frozen `7d7f050095` now passes the actual hermetic `golden-vectors` gate:
all twenty owning consumers execute 104 exact tests with no failures or ignored
cases, and all thirty-one reviewed sections have required consumers. Its 6,209
tracked source entries remain unchanged; the filtered build input matches all
5,155 included files, and independent review verifies all 268 retained packet
hashes. This earlier source result does not qualify the newer aggregate.
Reviewed test-only correction `b9a7821f3b` adds twenty-six bounded fixture markers
through a separate opt-in diagnostic, preserving existing trace calls and every
assertion. Composition `cf7fa4d256` passes actual all-target compilation with
source seals unchanged; its phase-only diagnostic remains pending. Twenty-six
independent core and foundation gates proceed on frozen `4a1ff5d5fb` with private
hermetic Cargo targets, separately from application and native qualification.
The bounded diagnostic times out after entering the reopened lookup. A separate
source-unchanged run streams the same markers with external timestamps: first
backfill takes 35.963 seconds including preparation, first current lookup takes
44.113 seconds, and the reopened lookup begins at 108.384 seconds. These
measurements identify cumulative fixture cost without establishing a deadlock.
The parent registers two additional mandatory backfill cases before their
implementation: protected reopen and maintenance of an existing required binding.
The worker separates these independent scenarios while retaining every original
assertion, genuine histories, populations, authority checks and unchanged limits.
The required read population grows from ninety-three to ninety-five cases; no
case is removed. Reviewed fixture-only implementation `34024000ff` preserves
all twenty-eight original assertions across three genuine independent histories
and additionally checks the reopened winning commit and exact object set.
Composition `759c4c9e52` passes its native build, strict all-target Clippy,
actual all-target test compilation and genuine executable-bound inventory of
1,004 cases. Its three positive backfill cases pass in 89.776, 87.857 and
19.569 seconds, respectively (197.207 seconds overall; run
`1135df38-0ed6-488b-b559-9ff32840da2b`). Both diagnostic trace variables are
unset, and the default 120-second process and original writer/reader budgets
are unchanged. All 6,209 tracked source entries and executable seals remain
unchanged. The mandatory ninety-five-case read qualification finishes with
ninety-four passes and one failure in 390.451 seconds on that frozen source.
The existing-binding case returns `Advance(Expired)` after 72.213 seconds;
its earlier focused pass does not qualify the failing aggregate. Source,
executable and raw-log seals remain unchanged. The dependent twenty-nine
native read cases, public SDK case and seven native key-limit/maintenance
cases remain unrun. A single bounded, source-unchanged diagnostic is assigned
to locate the expiry while preserving every deadline and authority check.
Both mandatory formatter commands pass on clean `759c4c9e52` with no edits.
Sixteen pack and four codec gates qualify separately on
the same candidate with private hermetic Cargo targets; the twenty-six core
and foundation gates and twenty-nine application target compilation retain
their earlier frozen `4a1ff5d5fb` source. The complete aggregate remains pending.
No owning gate or task is accepted by these results.
The same frozen retained-read candidate passes all twenty-nine mandatory
native read cases in 46.960 seconds and the public SDK case in 0.009 seconds,
with source and executable seals unchanged. Its unchanged backfill witness
fails after 82.167 seconds with a read authorization denial, rather than timing
out; no measured cause is established. The full ninety-three-case read run
therefore remains unrun. A separate direct-harness diagnostic uses the original
sealed native binary and AOS-built timeout at the unchanged 120-second bound.
It exits 101 after 50.020 seconds with `Advance(Expired)` during actual backfill
publication after durable staging: the retained writer elapsed 30.882 seconds
against its unchanged thirty-second limit. Original lock acquisition takes
54 microseconds; the longer reported scopes are retained lifetimes, not lock
waits. All 6,200 source entries, native executable and timeout seals remain
unchanged. The existing trace emits roughly 205 MB and adds overhead, so this
diagnostic neither establishes the original untraced denial's cause nor replaces
its failed Nextest qualification. Current assembled runtime remains required.
Parallel review also corrects a nested-overlay fixture's expected
projected property order without changing independent output identities or
weakening callback assertions. A complete decoder-call audit also identifies
the derived-object plaintext reader as an additional CDC-19 consumer; its
shared wiring now uses the object-context decoder, and the boundary gate
requires a dedicated exact reader witness. The reviewed fixture is composed
with honest content identities, canonical controls and refusal before returning
even a prefix before the cut; assembled runtime qualification remains pending.
Parallel review also identifies CDC-19's final manifest chunk boundary gap in
admission, restoration and guarded reads.
An isolated codec/manifest witness workline owns the correction; the exact native
nonfinal and final admission selectors are registered in `cdc-boundaries`.
The reviewed object-context decoder preserves standalone dictionary admission
and adds final-boundary verification; manifest admission and guarded object
reads use that helper. Source integration and executable qualification remain
pending, including the permanent restoration path.
Native overlay review also
identifies inherited index bindings that need authentication against their
signed source and recomputation for the actual output. Source corrections
and fixtures remain in that workline. Another review finds unreported planner
reconstruction; the native algebra workline replaces those redundant rebuilds
with qualified metadata traversal while preserving separately measured full
source reconstruction. Its source and runtime review remain pending; none of
these results accepts a task.
The owning gates and full current trunk floor remain pending. No diagnostic
run substitutes for qualification.
Unchanged-budget runtime tests and the complete current trunk floor remain
required before task acceptance.
The frozen `9d122397a6` native recovery run is terminal: all thirty-one
registered cases ran, with fourteen passes, eight failures and nine timeouts
(2,770.386 seconds; run `cf52bbd2-6224-4a3c-bf53-54dba13b7583`, raw log
`/tmp/terrane-native-recovery-corrected-full-nextest.log`). The public queued
renewal exposes a genuine namespace/Original-lock cycle. Existing-only shared
and exclusive nonblocking primitives now preserve actual inode checks and
retained native duplicates; both modes also have replaced-open-name witnesses.
This additive shared prerequisite does not yet change Original acquisition,
and its build and runtime checks remain pending. The reviewed next change
chooses read or write access before acquisition, refuses busy coordination
without retaining the namespace holder, and preserves exclusive live record
writers. No task acceptance or T1 exit follows from these source changes.
The composed prerequisite source `3fa2d42f1e` now passes strict native all-target
Clippy with warnings denied (34.87 seconds; raw log
`/tmp/terrane-reviewed-recovery-prerequisites-clippy-path.log`). The first check
found the explicit lease test module's child-path mismatch; the parent-owned
registration now names the existing witness file. The real known-empty
collection and both native try-lock witnesses pass all three selected tests
(0.835 seconds; `/tmp/terrane-reviewed-recovery-prerequisites-nextest.log`).
The inventory-verified Raw durability module also passes all twenty-eight
classification, actual syscall, freshness, refusal and cancellation cases
(0.315 seconds; `/tmp/terrane-current-durability-regressions-nextest.log`).
These are prerequisite results only. The public Original-mode conversion,
restore corrections, owning gates and complete current trunk floor remain
unqualified.
The reviewed public Original conversion and restore corrections are composed
on private `7b4689fcbc`. Its strict native all-target Clippy passes with warnings
denied (58.95 seconds; `/tmp/terrane-original-lock-restore-composition-clippy-corrected.log`).
The initial check exposed an incorrect directory-sync enum qualifier in the
restore producer; its existing imported closed `Plan` now resolves that effect.
Workspace Rust formatting also passes after a separate barrier let-chain
format-only correction. Seven native renewal, administrative-exclusion,
reconciliation and restore cases are running from this frozen source; no runtime
result is inferred before terminal evidence. A separately reviewed copied-sync
change removes only redundant whole-projection scans after complete worker
refreshes; it retains every consumed input and remains unqualified.
That seven-case run is terminal: four passes, two failures and one timeout
(473.940 seconds; run `e6e57598-6c63-4bb3-ba2f-6636a4c03039`,
`/tmp/terrane-original-lock-restore-focused-nextest.log`). Both actual
administrative lock tests pass, as do missing/corrupt-source refusal and fresh
secure restore preserving the permanent burn owner. Queued public renewal
now receives a genuine durable lease ACK; its old runner reports the exact
nested `LeaseLost`, instead of the fixture's expected Store denial. The reviewed
oracle correction preserves all subsequent physical, phase and source checks.
Recurring reconciliation now installs real mark/fence/event records, then
refuses its attempted portable projection of non-projectable GC keys. The
reviewed producer correction retains an empty portable delta with its genuine
predecessor and preserves every GC transaction change and cache repair. Both
corrections and the smaller copied-sync scan reduction await changed-source
qualification. Restore-preservation remains timed out; no task or exit is green.
Private composition `1d4405cf78` passes strict native all-target Clippy with
warnings denied (16.71 seconds; `/tmp/terrane-recurring-snapshot-copied-sync-clippy.log`).
Its changed-source focused run is terminal: one pass and two timeouts
(264.052 seconds; run `db52253a-36d6-4c17-91d9-29c4196cbcdc`,
`/tmp/terrane-recurring-snapshot-copied-sync-focused-nextest.log`). The public
whole-lease renewal and expiry case passes, including its exact physical and
source postconditions. Recurring reconciliation now completes its first pass
with genuine progress and reclaim acknowledgments; its next empty pass times
out during checkpoint installation. Restore-preservation also times out.
Independent normative reviews find no one-second durable renewal requirement
in GC-22 or D-82. A separate cadence task preserves immediate first-loop and
final renewal, full G/D, one-second immutable/clock checks and complete current
authority before every actual effect. Three parent-registered skipped-renewal
refusal witnesses extend the copied-first-ownership auxiliary from twenty to
twenty-three cases; their implementation and qualification remain pending.
No collector task or T1 exit is accepted by these results.
The existing 1,024-occurrence ordinary native index witness also fails on
`1d4405cf78` with `Advance(Expired)` during baseline publication (57.71 seconds;
`/tmp/terrane-current-raw-routing-1024-index-nextest.log`). Its writer budget
remains thirty seconds. The other five growing populations are unqualified;
Raw routing's passing small regressions do not establish DRV-29 performance.
The exact twenty native singleton/administrative cases, six roots cases, four
grace cases and fourteen marking cases all pass on `1d4405cf78` (44/44;
235.106 seconds; run `e0624c8b-81be-4a1d-9d35-d75d8d9291da`,
`/tmp/terrane-current-native-gc-44-nextest.log`). The independent non-Send case
and owning Nix checks remain necessary. Reviewed cadence composition
`8392c8964c` passes strict native all-target Clippy with warnings denied
(20.69 seconds; `/tmp/terrane-copied-renewal-cadence-composition-clippy.log`).
It preserves complete renewal/effect authority and cancellation poisoning;
its new native ACK observer is followed by actual selected-slot, transaction
and physical whole-lease checks. Changed-source runtime qualification remains
pending, including the two previously timed-out recovery cases.
The cadence focused run is terminal: five passes, one failure and one timeout
(487.450 seconds; run `56ed6a69-03e1-4d69-a16a-ca2e37814e54`,
`/tmp/terrane-copied-renewal-cadence-focused-nextest.log`). All three new
skipped-renewal refusals, actual queued public renewal/expiry, and the full G/D
witness with two genuine midwait ACKs pass. Recurring recovery reaches its
second completed pass, then its oracle incorrectly compares an initial null
proposal pointer with the hydrated original selecting slot. The reviewed
test correction independently resolves that immutable commit and transaction
and requires the exact original slot, preserving all other owner and state
assertions. Private composition `daf84d1cf0` passes strict native all-target
Clippy (10.27 seconds; `/tmp/terrane-original-owner-slot-oracle-clippy.log`);
its changed recurring run is terminal with one timeout at the unchanged
120-second bound (120.011 seconds; run
`a8c2857b-772b-4612-a7d7-47131347b8f6`,
`/tmp/terrane-original-owner-slot-recurring-nextest.log`). Its trace reaches
selected progress and actual reclaim, but does not complete the late-residue
and reopen assertions. Restore-preservation still times out before its
copied-barrier request returns. Source review identifies recursive retained
pair wrappers: each additional pair doubles the earlier checks on every Frame
refresh. The reviewed private helper and both collector consumers now retain
the complete genuinely acknowledged prefix and observe it forward and backward
from one original current check, including the copied barrier where required.
For a nonempty prefix of k pairs, each refresh makes 2k-1 pair observations;
current authority is checked before the first and after every observation.
Physical effect and acknowledgment boundaries remain unchanged. Static first
observations preserve inventory order; transient first-error order can differ.
No measured timeout cause is inferred from the source cost correction.
Private composition `0e09995dca` passes strict native all-target Clippy with
warnings denied (28.82 seconds;
`/tmp/terrane-linear-pair-recovery-clippy.log`). Its recurring late-residue and
two fresh-placement restore cases are terminal with three passes and 908 skips
(280.061 seconds; run `cd067ab4-9695-4fa5-90d0-350813e5a747`,
`/tmp/terrane-linear-pair-recovery-focused-nextest.log`). Private composition
`7ef8cb644b` also passes strict native all-target Clippy (15.79 seconds;
`/tmp/terrane-linear-pair-witnesses-clippy.log`) and both actual retained-prefix
replacement and canceled-worker exclusion witnesses (2/2, 911 skips;
6.489 seconds; run `501d88d8-3e38-46ea-8454-6ae4f56337ba`,
`/tmp/terrane-linear-pair-witnesses-nextest.log`). These focused results do not
qualify the owning reconciliation gate. Its twenty-three-case Nix request
fails on the first large-family recovery case after 252.31 seconds with
`gc-checkpoint` denial of the current configured collector session; the other
twenty-two cases do not run (`/tmp/terrane-linear-pair-permanent-owning-nix.log`,
`/nix/store/pcl885h2mglffvlss14cmqzbv5z7y5ss-terrane-gate-local-permanent-reconciliation-0.1.0.drv`).
The configured ninety-second session and 4,100 additional trash directories
remain unchanged. Source renews once before recurring reconciliation; the
log does not establish per-stage cost or the measured cause of expiry.
A separate recovery task reviews genuine renewal at borrow-free handoffs.
Owning checks and the complete T1 floor remain unqualified; no task or exit
is accepted by these results.
The reviewed renewal candidate `072c4c5d78` now acknowledges a genuine
whole-lease renewal at each observation-loop entry, after previous checked
borrows have ended. It keeps progress and its corresponding reclaim under
the same exact Planned-event lease. Strict native all-target Clippy passes
(14.36 seconds; `/tmp/terrane-permanent-renewal-clippy-loop-only.log`). Its
two-case recovery run is terminal with one pass and one timeout (228.230
seconds; run `6b69c814-4f03-4a93-b97f-eec2ca8ca073`,
`/tmp/terrane-permanent-renewal-focused-loop-only.log`). The empty/late-residue
case passes genuine multiple-renewal ACK and actual selected-chain checks.
The 4,100-cycle case times out at the unchanged 120-second bound after real
observation, progress, reclaim and loop-renewal acknowledgments; its next
progress publication remains unfinished. The ninety-second session, population
and all lease-equality predicates remain unchanged. The log establishes no
per-effect cost or measured cause. The owning twenty-three-case check and
complete T1 floor remain unqualified, and T-GC-1 remains open.
The retained native Node scope candidate `90648cf430` passes strict all-target
Clippy with warnings denied (46.87 seconds;
`/tmp/terrane-held-node-scope-native-clippy-final.log`). Its thirteen-case
runtime selection is terminal: nine passes and four failures, with 913 unrelated
tests skipped (58.422 seconds; run `1648dc15-9de1-46e9-af61-f948826c30e7`,
`/tmp/terrane-held-node-scope-13-nextest.log`). Three fixtures assume that two
Nodes occupy the same pack, but actual native batching and existing-member
deduplication place them separately. Correction `bca8f05fdc` stages two distinct
new ordinary Nodes in one actual metadata run and preserves the exact pack,
cancellation and incompatible-role assertions. The fourth failure shows that
the retained selected scope omits the selected protected Guard's original
physical recipe: an equal-byte Guard inode replacement survives its test-only
DATA closure. The owning Guard producer already retains its separate initial
Guard read; this result does not establish a semantic publication bypass.
Shared correction `8bdceed83d` captures the selected Guard through the original
held protected reader, validates its exact digest and schema, and includes it
in that scope's physical ledger. Combined candidate `c0f87d4e56` preserves the
seven original loading selectors and requires all thirteen new witnesses. Its
strict native all-target Clippy passes with warnings denied (46.61 seconds;
`/tmp/terrane-held-node-c0-native-clippy.log`). The corrected thirteen-case
runtime selection now passes all thirteen with 913 unrelated tests skipped
(59.158 seconds; run `c630e668-cdc3-4e3d-8b59-451f1da60d14`,
`/tmp/terrane-held-node-c0-scope-13-nextest.log`). This closes the four reported
fixture and selected-Guard physical-ledger failures. The unchanged 1,024-record
publication, other five population cases, twenty-case owning loading check
and complete T1 floor remain unqualified. No task checkbox or milestone exit
advances.
The first unchanged 1,024-record ordinary publication on `c0f87d4e56` is
terminal with `Advance(Expired)` (56.488 seconds, one failure, 925 unrelated
tests skipped; run `435e2846-a53d-4873-a517-a069c925928b`,
`/tmp/terrane-held-node-c0-1024-ordinary-phase-nextest.log`). The genuine retained
deadline first refuses at 30.008514493 seconds against the unchanged thirty-second
maximum, during output directory synchronization. Its real phase trace records
22.639387041 seconds from catalog-cohort publication entry to acknowledgment;
candidate history returns after a further 1.552987296 seconds and final
dispatch begins at 27.234916705 seconds from the original deadline origin.
These observations locate the expensive interval without proving a particular
source correction or relaxing current, physical or deadline predicates. The
other five populations and twenty-case owning loading check remain unrun.
Shared source correction `acc3f14622` coalesces original physical input rows
only when every checked constraint agrees. It retains the first original
recipe unchanged and ignores only directory link-count differences already
ignored by native incarnation checks; regular-file link counts, complete bytes,
policies, ancestry and exclusions remain distinct and freshly checked.
Its measured benefit and runtime correctness remain unqualified. Registration
`029dbe2926` preserves the twenty loading selectors and adds three required
real-filesystem predicate witnesses, expanding the owning loading check to
twenty-three cases. Those witnesses remain unimplemented at registration;
requesting the check fails until every declared case exists and passes.
The private native candidate `fe73757d63` now implements all three witnesses
with actual held captures, real directory link growth, unchanged first recipes,
distinct body/policy/mode/inode/ancestry/descriptor observations and fresh
native refusals before synchronization. Absent leaves and parents that appear
later also refuse; no selected authority or success acknowledgment is fabricated.
Review corrected test helper calls to satisfy the workspace's `expect_used`
restriction without allowances. Scoped formatting and diff checks pass; compile,
runtime, portable compatibility and publication-budget qualification remain
pending. Existing owning witnesses still supply cancellation and owner checks.
Its first strict std-only all-target Clippy run fails with nineteen native-only
import and helper diagnostics. Reviewed five-file correction `82183ac620`
preserves ordinary ancestor-first validation while gating native held readers;
strict std-only all-target Clippy then passes in 39.83 seconds
(`/tmp/terrane-portable-history-82183ac-std-clippy-escalated.log`). The subsequent
native check identifies a missing explicit nested test-module path; shared
correction `2f3dcec19c` resolves it. Native all-target Clippy on private composition
`7bb347c194` then fails only on two unused collector proposal test helpers whose
consumer witnesses are not composed there. This is not a native lint pass.
The native-index candidate `b2f541b1c3` now composes only the reviewed portability,
module-path and native feature boundaries, preserving its existing paired
exclusions and read projection. Its strict native all-target Clippy passes with
warnings denied (1 minute 3 seconds;
`/tmp/terrane-predicate-b2f541-native-clippy.log`). All sixteen exact regressions
pass, including the three actual-filesystem predicate witnesses (63.275 seconds,
913 unrelated tests skipped; run `6ca5db87-1002-482d-9158-954b34f689a2`,
`/tmp/terrane-predicate-b2f541-scope-16-nextest.log`). Test-target compilation
takes 6 minutes 32 seconds. The unchanged ordinary 1,024-entry witness, other
five populations, owning twenty-three-case gate and full T1 floor remain
unqualified; these focused results do not advance task acceptance.
The first unchanged ordinary 1,024-entry execution is now terminal with one
timeout at 120.011 seconds, zero passes and 928 unrelated tests skipped
(run `48fea501-2356-4977-a579-5584f7669f5a`,
`/tmp/terrane-predicate-b2f541-1024-ordinary-phase-nextest.log`). Its baseline
publication reaches an actual selected durable acknowledgment in 26.003029672
seconds, within unchanged C30. The final raw durability scope retains 69 names
and 534 exact reads and performs 224,711 fresh attempts across 745 refreshes;
the earlier `c0f87d4e56` scope retained 94 names and 954 reads and performed
394,955 attempts. These are actual row reductions, while cross-run elapsed
differences do not establish calibrated attribution. After acknowledgment,
ordinary history verification takes 43.632733163 seconds; 1,033 subsequent
plain-read scope entries precede timeout. Independent-work and maintained
publication phases are not reached. No retained deadline refusal appears in
this execution before timeout. The whole witness remains failed; no population
or deadline is omitted or relaxed. Source diagnosis now targets the measured
ordinary history and immutable-read interval.
The reviewed permanent recovery candidate `b0d2b176f0` retains original
directory continuity while staging fresh, unselected progress proposals and
restores full canonical candidate enumeration before preselection directory
synchronization, keeping it through selection and acknowledgment. Actual
current inputs, absent checkpoint preimages, exclusions and physical recipes
remain checked. Its production native build passes (25.31 seconds;
`/tmp/terrane-permanent-stage-build.log`). Eleven new genuine proposal-handoff
witnesses cover directory and current-input mutation, cancellation and fresh
recovery of added late residue. Source review identified eight overly broad
Store-failure assertions. Correction `373333121f` now pins the exact unavailable
kind and first native named-fence, policy, candidate-timestamp or preimage
diagnostic. Independent source-order review confirms those expectations;
their actual runtime and changed test-source lint qualification remain pending.
Strict native all-target Clippy on corrected witness source `373333121f` now
passes with warnings denied (59.41 seconds;
`/tmp/terrane-permanent-stage-clippy-373.log`). The eleven runtime witnesses
are now terminal after cancellation of the verified owned coordinator
(268.360 seconds; run `42c988c9-1701-4860-bb40-0c38ddc2d202`,
`/tmp/terrane-permanent-stage-focused-373.log`). Three cases fail in shared
fixture setup before takeover, proposal pause or fault injection because the
actual reservation directory has not been created. One case is interrupted;
seven remain unrun. These results establish no staging refusal or recovery
behavior. Test-only correction `e3ce9e839e` treats actual nofollow `NotFound`
as empty reservation inventory while preserving safe kind, owner and mode
checks for existing directories and exposing other failures. Its scoped
formatting and diff checks pass. The corrected requested-directory-policy
smoke witness now passes on `e3ce9e839e` (85.122 seconds, one pass and 923
unrelated tests skipped; run `f7eddb22-b5e4-44a2-b275-152ed8f1d344`,
`/tmp/terrane-permanent-stage-smoke-e3.log`). It reaches the real roots-proposal
handoff and checks the exact unsafe physical-fence refusal, absence of selected
progress/reclaim and preservation of owner/pass/manifest. The complete eleven
staging witnesses, owning reconciliation gate and large-family bound remain
unqualified; this smoke result does not advance T-GC-1.
The subsequent unchanged eleven-case matrix is terminal: ten cases pass and
the added-cycle witness times out at 120.004 seconds (994.963 seconds for the
matrix, 913 unrelated tests skipped; `/tmp/terrane-permanent-stage-focused-e3.log`,
run `cbb1472a-42dc-407d-a4ba-23ef71c2decb`). Passing witnesses cover requested
directory replacement and policy, off-batch policy, removed/noncanonical/symlink
cycles, expired whole-session lease, replaced owner and Original preimages, and
cancellation with native reopen. The added-cycle case reaches genuine fresh
recovery and an actual late-pack reclaim return; its final progress seal is
submitted but has no return before timeout. Whole liveness and completed-pass
acknowledgment remain unqualified. No per-effect timestamps establish which
operation caused the elapsed failure.
Reviewed collector source `c15c9349c1` now borrows a first-match path index for
retained directory recipes, preserving the first actual recipe and all duplicate
rows, fresh physical checks, full enumeration and synchronization boundaries.
Opt-in phase observations cover genuine reconciliation, proposal staging,
native progress sealing and completed-state reopen. Lookup complexity motivates
the change; no measured timeout cause or runtime benefit is claimed. Its scoped
formatting and diff checks pass, but changed-source compilation and the unchanged
added-cycle liveness witness remain pending.
Strict native all-target Clippy also passes with warnings denied (5 minutes
5 seconds, including a recorded wait for an external shared-target lock;
`/tmp/terrane-permanent-stage-clippy.log`). This elapsed observation does not
measure source-stage cost. The expanded thirty-four-case owning reconciliation
gate and the unchanged large-family recovery bound remain unqualified. Neither
staging continuity nor build and lint results establish collection coverage.
Four additional isolated T1 workers now carry independent portability,
recorded-property caller, ext4 workflow and format-conformance work. Their
source branches remain private qualification candidates. Recorded caller
coverage `fab8ca3014` invokes actual repository file/view readers for ref and
fixed-commit targets across revisions 1 to 3, with real Original and current ACL
refusals. Ext4 workflow source `e1fd4486a9` adds actual guest authority refusals
and retains the writable image and packaged binary identity; source formatting,
shell syntax and derivation dry-run pass, but no guest execution is claimed.
Format source `2779bc9ffb` adds independent nonempty contextual carrier models;
shared registry `2925be47f4` requires the new exact group, expanding the public
property catalog from 58 to 59. Structured JSON/catalog consistency and scoped
formatting checks pass; actual format execution remains pending. Heavy builds
and deadline tests are serialized while source work proceeds in parallel.
These source changes and partial results do not advance any T1 checkbox.
The corrected format candidate `7724cb4ded` now passes strict all-target Core
Clippy and all 59 public property groups with zero skips. Its first execution
found one fixture incorrectly expecting generic encoding to accept an empty
Index target set. The correction pins the actual generic `Entry` refusal and
retains the independently encoded contextual refusal; no property is removed.
The actual `core-fuzz` gate passes all 59 public groups and five required
private encoder cases. `canonical-cbor` also passes. Their original logs are
`/tmp/terrane-format-7724-core-fuzz.log` and
`/tmp/terrane-format-7724-canonical-cbor.log`. The original `golden-vectors`
request is now terminal with exit zero: all twenty mandatory owning suites,
thirty-one reviewed sections and 104 exact runtime invocations pass. Its
result is `/nix/store/s5m57zgzfsq9gprlrlaljdsc5q2ac6i0-terrane-gate-golden-vectors-0.1.0/result`;
the original log is `/tmp/terrane-format-7724-golden-vectors.log`. Final private
`6e1f256ad4` adds only the reviewed coverage-text correction; Rust and gate
inputs remain byte-identical to qualified `7724cb4ded`. These scoped results
do not qualify the complete T1 floor or advance T-TEST-1.
Shared source `51d39c7771` batches payload namespace ancestor metadata while
retaining the separate root check, ordered first refusal, exact batch length
and final leaf observation. The bucket-file-layout gate now requires three
additional actual-filesystem witnesses, expanding its exact inventory from
nineteen to twenty-two. Private `338b4476a2` implements those cases against
an independent scalar recipe, with real unsafe nodes, absent paths and named
I/O errors. Shared `cb537248e8` and its private composition add test-only
phase observations around ancestor batches, leaf dispatch and ordinary content
reads. Source formatting and diff checks pass; changed-source build, runtime,
owning gates and the unchanged 1,024-entry population remain unqualified.
A separate current-T1 SDK audit identifies the named attribute `get` interface
in CRATE-25 as missing, although public SideTable lookup and put already work.
An additional isolated worker owns only the existing table implementation and
a public integration consumer; shared gate prerequisite `5162673a56` retains
all existing attribute tests and requires that consumer. This is source
registration, not API or runtime qualification. Remote verbs and tree jobs
remain in their later milestones and branch worklines.
The reviewed attribute SDK candidate `376328f9ad` now implements documented
`SideTable::get` over the existing exact metadata lookup. Its public consumer
uses signed producer/tree evidence, retains unsupported and unsigned records,
checks metadata-only reads and pins storage and invalid-signature failures.
Scoped source formatting passes; compilation and runtime remain queued.
Private composition `e64fd484f1` now combines all six reviewed task branches
without changing the PR branch's implementation or acceptance. Its six merge
commits preserve task ancestry. Independent source verification matches all
6,171 tracked files and all 34 expected source paths, retains the newer held
history/read machinery, and preserves the 59/23/34 format/index/recovery
inventories and current shared gate metadata. No conflict markers remain.
This is preparation for the complete T1 floor; it establishes no compiler,
runtime, gate or milestone result. With the format request terminal, recovery
qualification has started on its frozen source. Its original strict native
Clippy process first waited for the shared Cargo build-directory lock, then
terminated with exit 101 on three production references to a test-only tracer
(`/tmp/terrane-permanent-lookup-clippy-c15.log`). Private `42161fb184` guards
every added diagnostic call with `cfg(test)` and leaves all physical checks,
lookup and ACK boundaries unchanged. Its strict native all-target Clippy and
fresh 924-test inventory pass. The single unchanged AddedCycle witness fails
with TIMEOUT at 120.016 seconds, before proposal handoff or fault injection.
Its own-fixture interval is 85.500310393 seconds; the actual initial observation
returns successfully after 19.862431354 seconds from current/history qualification.
No late-residue recovery, takeover or final ACK is inferred from this run.
The earlier late-reclaim timeout remains separate evidence. Full recovery and
milestone gates remain unqualified.
Three additional workers now implement disjoint parts of the ordinary-read
closure: one request-local selected observation, bounded pack framing/member
reads, and genuine descriptor-bound original range receipts. Independent
source review confirms an inherited STORE-4 violation: an intra-chunk range
currently reads the whole pack before slicing. The existing range gate checks
returned bytes and overflow but does not refuse whole-pack I/O. T-BKT-1 is
reopened; its gate now requires seven actual ranged-I/O witnesses, while the
verified-get gate additionally requires nine request-local closing witnesses.
Missing selectors fail explicitly. No task or runtime result follows from
these source prerequisites; deadlines, populations and failure evidence remain
unchanged.
Reviewed range-receipt source `6f8daefd82` now supplies original leaf and ancestor
descriptors, actual bounded reads and fresh closing checks without publication
or actor authority. The shared LocalFs hook returns explicit unsupported
execution by default; its native binding executes owned recipes through the
blocking worker. Eight exact helper witnesses join runtime-agnostic without
removing existing cases. Private adapters remain native-only; opaque hook types
preserve portable trait compilation. Source formatting passes, but compilation,
helper execution and range integration remain unqualified. Ordinary whole
artifact and selected snapshot/log receipts still need an ordinary read policy;
existing strict publication recipes cannot impose new owner or hardlink rules
on copied ordinary payloads. The selected-get candidate remains unqualified
until that compatibility bridge and complete closing witnesses are implemented.
Implementation now proceeds in disjoint worklines for the ordinary receipt
bridge, read-only retained selection, and bounded legacy/read-only/unsupported
fallbacks. A separate full source review checks the bounded reader. Reviewed
bridge `e5715a24bd` retains real whole-artifact descriptors, bytes and metadata,
preserves initial public modes and hardlinks, and marks ordinary receipts so
protected Frame inputs refuse them. Shared contextual capture and strict recipe
attachment also reject these ordinary receipts before importing observations.
Four exact ordinary-receipt witnesses join runtime-agnostic. Source composition
preserves current trunk functions and excludes unrelated private GC changes;
compilation, witness execution and task acceptance remain pending.
Corrected ordinary-read candidate `3ff271f871` passes strict native all-target
Clippy and fresh inventory binding of all 93 required witnesses. Its unchanged
default-profile run completes in 307.586 seconds: 92 PASS and one existing
required-inline/index backfill TIMEOUT at 120.006 seconds. All three new
namespace witnesses and fourteen original ordinary-read witnesses pass; this
does not qualify the whole candidate. Its source and executable hashes remain
unchanged. Owning gates, the 1,024-record witness and full application/format
checks remain unrun. The original native missing-method failure remains
separate failure evidence. The new bounded/read-only integration is being
composed with reviewed diagnostic and fixture corrections for fresh qualification.
The shared final-check producer now retains the native permanent-family
traversal through pre-selection handoffs. Its typed receipt refreshes actual
enumeration and directory continuity between current-authority checks;
selected current-pass history remains the separate coverage proof. This shared
prerequisite is source-only until the task's receipt implementation is composed
and qualified. The five permanent fault fixtures now include an independent
canonical coordination-lock exclusion oracle after waiter cancellation and
remove fixture storage only after actual native workers terminate. Their
compilation and runtime checks remain pending. No task or exit is accepted by
these source changes (GC-15, GC-16, GC-24 and GC-29).
The strict std-only, non-Send all-target Clippy check on private `d03e3b3275`
failed with two production receipt-sharing diagnostics and twenty-nine Scope
fixture assertion diagnostics. Feature-appropriate `Rc`/`Arc` retention and a
test-module-only intentional-panic allowance are privately composed on
`3cd0f06c1a`; the same actual AOS Clippy command now passes with warnings denied
(2026-10-09, raw log `/tmp/terrane-std-all-target-clippy-corrections.log`). This
qualifies that standard-library profile only. The full matching non-Send library
Nextest profile also passes all 217 tests with zero skips (run
`8602f827-a23d-477b-9f6b-8c379e35767a`, raw log
`/tmp/terrane-3cd-std-nextest.log`). The new Tokio recovery fixtures, native
traversal selection and runtime gates remain unqualified.
The reviewed continuation now removes total-family caps while bounding each
event, reconstructs current-pass coverage and unresolved duties from actual
selected history, and attaches the typed native traversal refresh immediately
after genuine Frame capture, before progress writes and selecting-slot effects.
Its private composition `f5d6069445` passes strict Tokio production-library
Clippy with warnings denied (raw log
`/tmp/terrane-bounded-traversal-production-clippy.log`). Each event still scans
the complete family and reconstructs history; this pass does not prove runtime
fairness, large-family performance or the new native test-target compilation.
All nineteen copied-retirement and eleven permanent-recovery test functions are
now privately composed on `36f987ad14`. The first actual strict all-target check
with the owning `tokio,surface-sdk` profile stops on four exhaustive probe
matches in existing ref, cold-fork and creation harnesses (raw log
`/tmp/terrane-native-recovery-all-target-clippy.log`, exit 101). The shared
harnesses now classify the six new closed native effect kinds explicitly while
preserving existing forwarding and fault predicates. The two descendant helper
files are carried from the frozen private composition; their only subsequent
changes are these classifications. Combined compilation, lint and runtime
remain pending; this is no native gate pass or task acceptance.
The corrected native all-target check on `ac701f367a` reaches strict lint and
stops only on the two unused synchronization boundaries in the shared
permanent test hook (raw log
`/tmp/terrane-native-recovery-all-target-clippy-corrections.log`, exit 101).
The cancellation witness now exercises both boundaries alongside BeforeOpen,
checking the actual independent coordination lock, native terminal outcome and
fresh recovery after waiter cancellation. These added scenarios are source-only.
The copied first-ownership auxiliary additionally registers the real unused-Memo
and shared-live-Index regression, raising its exact inventory from nineteen to
twenty without changing gate names or observation bounds (GC-5, GC-24, GC-29).
The complete private native source `b47f260281` now passes strict all-target
Clippy with `--no-default-features --features tokio,surface-sdk` and warnings
denied (raw log `/tmp/terrane-native-recovery-borrowed-all-target-clippy.log`).
This includes the thirty-one actual copied/permanent test functions, the
4,100-cycle continuation and genuine reopen additions, and all three native
cancellation boundaries. The matching serial Nextest run has started with
unchanged clocks and bounds; runtime results and owning Nix gates remain
pending. No additional task or milestone exit is accepted by compilation.
That run finishes its actual thirty-one-case inventory with two passes,
twenty-five failures and four timeouts in 601.006 seconds (exit 100; run
`577042b0-9809-47d7-8434-384e67f8853f`, raw log
`/tmp/terrane-native-recovery-full-nextest.log`). Multiple copied first-owner
fixtures fail before ownership with a missing exact detached-index preimage;
the copied producer submits an eligible DATA-pair check before retaining its
genuine observed index read. Several dependent hook cases reach the existing
120-second process timeout. A separate fallback fixture compares encoded
chunk bytes with an unencoded payload. All eleven permanent fixtures fail in
their first-owner prerequisite before reaching permanent recovery or restore.
The two passing cases cover only negative refusal. The worker has sealed the
genuine index capture, verified codec-envelope oracle and unused-hook closure
corrections; combined runtime qualification remains pending. No native gate or
task acceptance follows (GC-15, GC-24, GC-29).
The private corrected source `054921610a` now passes the same strict native
all-target Clippy profile (raw log
`/tmp/terrane-copied-preimage-api-all-target-clippy.log`). Its preceding
composition `25506ff107` failed with three test API errors; the corrections use
existing canonical ref reads and explicit publication error inspection without
changing production receipt traits. The actual whole-lease witness queues a
real renewal behind the held barrier and checks its selected durable value;
its refusal may precede native ownership dispatch and proves no ownership ACK,
not an in-worker refusal. Four focused runtime cases have started with unchanged
bounds; that run finishes with one pass, one failure and two timeouts (run
`85b6db8f-4402-402f-8edd-b9685ad15bcd`, raw log
`/tmp/terrane-copied-preimage-focused-nextest.log`). Missing selected history
now refuses correctly, while positive ownership and whole-lease change time out.
The fallback oracle additionally mixed the pack reader's verified plaintext
with serving's encoded envelope; the corrected assertion compares verified
plaintext without changing native permissions or inputs.
The next private source `9d122397a6` adds test-only actual effect/lock tracing
and that codec-oracle correction. Both exact positive all-absent first ownership
and burned-fallback refusal pass in one 126.038-second run with unchanged bounds
(run `5467c18a-ab1a-48cd-bad9-b1e946f7ed95`, raw log
`/tmp/terrane-copied-native-boundary-trace-nextest.log`). No production code
changed between those two runs, so the earlier timeout's cause is not established.
The matching full thirty-one-case runtime has started (run
`cf52bbd2-6224-4a3c-bf53-54dba13b7583`, raw log
`/tmp/terrane-native-recovery-corrected-full-nextest.log`). Its first ten
completed cases include seven passes and three failures; the original process
remains live. The positives include all-absent and index-only first ownership,
lineage removal with preserved burns, and complete live DATA without a foreign
Original. Source review traces the three failures to distinct refusal oracles:
a changed Guard incarnation returns the producer's exact destination-plan
denial, while deliberately unexecuted owner and preparation slot renames fail
the install command's actual destination reread as corruption. The private
worker seals narrow test corrections on `f0a16ae620`, retaining absent-slot,
no-ownership acknowledgment, source and barrier assertions. These corrections
are not composed into the live run and remain unqualified. Full native
qualification remains pending. The inventory audit finds
that every admitted writable native selection validates known ref, catalog and
exclusion inventories. Unknown legacy inputs remain read-only: their ref
enumeration returns `Unsupported`, and Original/held mutation admission refuses
them before effects. Existing `gc-roots-complete` and `bucket-cap-probe` cases
cover rejected incomplete successors and that legacy boundary. Their actual
owning-gate qualification is still required; a fabricated unknown writable
selection would not be valid collector evidence (GC-2, GC-29).
The parent registers a sixth `gc-roots-complete` case for genuine collection on
the freshly admitted known-empty ref inventory. Its isolated source is sealed
on `2206323347`: the real native lease fixture's Guard and Original independently
observe explicit empty selected inventories, publish and finish an empty-root
snapshot, then reopen and resume its unchanged Sweep progress. Parent and
independent review verify physical checkpoint bytes against the protected
commit/transaction and portable snapshot, with fresh selected revalidation.
This positive is distinct from read-only unknown-inventory refusal and proves
neither takeover nor destructive recovery. Source formatting and diff checks
pass; compilation, runtime and owning-gate qualification remain unrun while
the existing recovery process owns the build lane. No task is accepted.

The copied portion of that run completes fourteen passes, three refusal-oracle
failures and three timeouts. The queued public renewal trace and source expose
a genuine lock-order cycle: renewal retains namespace exclusion while waiting
for Original controls retained by the barrier, whose runner needs the namespace
again. A test-only inherited-control seam would not fix the public API. The
administrative writer audit also finds live association/import/trust writers,
so changing every Original lock to shared would be unsafe. Production acquisition
handling remains pending under GC-22 and GC-24, with all writer exclusions and
native in-flight retention preserved. Reopen times out at final ownership
submission; the unused-Memo case times out during native index setup before any
copied preparation. Those observations establish neither the same lock cycle
nor a deadline remedy.

The first permanent cancellation matrix times out before any permanent request:
all three independent fixtures have submitted first ownership without an ACK.
The parent registers every fault scenario as its own exact process, expanding
the auxiliary permanent inventory from eleven to twenty-three while retaining
all existing helpers, sixty-second barriers, fault assertions and the ordinary
120-second process bound. Outer Nextest scheduling reserves the runner slots
for copied and permanent cases. Isolated source adaptation and runtime proof
remain pending; the current thirty-one-case run is unchanged and still live.
Separately, the private Raw durability candidate `01f22fb6f4` merges immutable
ordinal indexes for consumed rows and current-target outputs. Full diff review
finds preserved duplicate attempts, physical check order, fault pre-scan and
first-refusal diagnostic prefixes, with an independent full-scan oracle.
Formatting and diff checks pass; compilation, regression gates and the six
unchanged index populations remain unrun. No speedup or acceptance is claimed.

All ten
exact native Active completion cases pass on `4e6c14a7f3`. The eight-case native
Legacy cold-fork gate now passes on `e2416dcdec`, including the exact fresh
Commit catalog Raw-to-Candidate sequence; its earlier predecessor-revision
failure is resolved. Recorded core changes on `24e005497d` pass all 529 tests,
fifteen exact owning cases, strict Clippy, private rustdoc and the no-std gate.
The private memo fingerprint includes the complete verified evidence and both
configured and occurrence selections without changing registered bytes.
D-105's independent ordinary scalar revisions are now accepted without granting
the exact 3/2/1 executable carrier profile. Unknown revisions and wrong
vocabularies remain refused; the property gate requires the owning scalar check.
The native Recorded implementation passes its production builds and all 132
default tests. Its preceding composed SDK run passes 367 of 477 tests and
fails 110. The correction separates constructor-selected current configuration
from authoring inputs while retaining exact snapshot comparisons and checked
reload rules. Its first focused run passes 15 of 21 cases; the remaining
failures lead to ordinary scalar, genuine producer-input and canonical
ancestor-scope corrections. The subsequent 25-case run passes 24 cases and
fails the Fold inspector's CBOR-null opcode assertion. Correcting that assertion
to the decoder's actual byte on `44972fa5c5` passes the exact Fold case.
The subsequent full SDK run on `876e80f048` passes 465 of 477 tests with no
skips. All 25 Recorded, historical, Fold and current-context cases, and all ten
cold cases, pass within that same run. The twelve remaining failures include
two Active fixtures, portable-copy admission, metadata callback accounting,
physical retirement and ordinary publication/provenance cases. Strict profiles
and task gates remain pending. Subsequent fixture corrections on `5b6e9e04ba`
pass the two exact Active cases, the fork's actual inherited entry and attribute
origins, and the metadata callback ordering case. These focused passes do not
replace the preceding full SDK result.
The composed Core library builds on `15798d9358`; mechanical test-helper ports
on `ac3d8ffb2c` allow the full run to execute all 698 tests. It passes 683 and
fails fifteen with no skips. The failures include historical defaults, selected
property errors, affected-root policy flags and genuine history/evaluator
fixtures. Reviewed corrections on `06f87a86e4` pass all 700 Core tests with no
skips, strict all-target Clippy, private rustdoc and the no-default-features
build. The registered `core-no-std` gate also passes through `aos-dev`; its
actual Nix source matches all 348 committed Core/Cargo inputs. Empty owner
defaults compare as the same namespace policy as absence, while explicit raw
edits and nonempty binding changes remain changes. Genuine independently
configured disclosure histories retain their original scope and role-refusal
checks. Runtime composition and the combined trunk floor remain incomplete.
Private backfill on `4f4bd8083f` passes all four exact cases, including
the formerly expired completeness case. All six publication batch cases also
pass. Its first finite qualification stops on missing-pack recovery with
`Corrupt(Pack)` after 2.61 seconds; subsequent phases are unrun in that attempt.
The reviewed fixture correction on `a6470b4450` separates the selected Node's
pack from its signed Commit before injecting the missing placement, retaining
all recovery and corruption assertions. The next finite run passes all seven
recovery, eight historical-completion, four Raw durability and nine current
control cases. It then stops in the default strict Clippy profile on three
host-clock calls in opt-in test diagnostics. Remaining profiles, private docs,
application compilation and both formatters are unrun. The test-only diagnostic
allowance on `7a959cccb6` passes default and std-send Clippy/private docs.
Native Clippy stops on four mechanical batch-test helper diagnostics; native
docs, application compilation and both formatters remain unrun in that attempt.
The reviewed mechanical helper correction on `c735446b74` passes Clippy and
private documentation in all three profiles, the mandatory application
test-target compilation, Rust formatting and repository formatting. Its actual
Nix source matches the frozen candidate throughout. The preceding 28 runtime
passes remain evidence from `a6470b4450`; runtime tests are not replayed in the
quality run, and combined qualification remains open.
D-111 preserves historical bytes while validating the independent current
revision. Shared property/algebra gate
mappings require actual owning witnesses and retain native Fold context coverage.
No task merge, checkbox,
milestone exit or freeze advances.

The runtime composition of Native `7d5aae71e2` and Core
`06f87a86e4`, including Private `4f4bd8083f`, now builds with
`std,send,tokio,surface-sdk`. Reviewed observation, field and configuration-adapter
ports resolve its initial seventeen compiler errors and two subsequent lifetime
diagnostics. The composed Core suite passes all 704 tests with no skips; it
retains the independently selected side-attribute resolver and four genuine
history-union/current-fence cases from Native. All 6,024 captured source files
remain unchanged through that Core qualification. Subsequent reviewed fixture
ports resolve the four test-only conflicts. Native test compilation initially
reports eight interface errors; bounded compatibility corrections then compile
and discover 704 library cases and five public SDK integration cases. All
nineteen literal native gate selectors, including the three relocated ordinary
merge contracts alongside the three native contracts, exist in that inventory.
Discovery executes no tests. Strict warnings, later fixes, native runtime and
the complete trunk gate set remain unqualified; no task or milestone advances.

The frozen combined candidate `9c59d60735` completes the full native suite:
709 tests run, 594 pass, 108 fail, seven time out and none are skipped. The
original run exits 100 in 2,178.243 seconds. Independent review verifies its
terminal log and all 6,025 bound source contents, resolving the `CLAUDE.md`
symlink to its tracked target. The failure inventory includes publication
expiry, denied admission, malformed inputs, missing index bindings and test
timeouts. Two isolated same-source portable-copy diagnostics pass; these
focused results do not replace the failing full suite or establish its cause.
The reviewed upload baseline correction measures required physical validation
and final placement rechecks, preserving exact read and effect assertions.
All four selected upload cases pass on `daf085bc11`; the successful case
requires all 109 reads and reduces selected reads from 72 to 54. Its owning
`bucket-file-cas` and `store-verify-on-get` Nix gates pass all 45 and twelve
exact cases respectively. The existing qualified retention/imported-source
dependency `9d5cd28c33ae`, absent from the original run, is normally merged
into the private composition at `09a21494ad`. A separately reviewed synthetic
restore assertion now requires exact missing-protected-intent corruption;
copied-burn refusal and unchanged-state assertions remain intact. These
changes and the active-index/ordinary-merge corrections still need combined
qualification. No task, milestone exit or freeze advances.

The active-index correction on `d3c65a3bc2` passes six fresh exact regression
cases. It preserves absent-binding incompleteness while the writer independently
refuses dropping a required binding; present missing bodies and divergent
relationships still refuse. Its native Active gate passes the first eight
cases, then fails the unchanged generic Index metadata fixture. TREE-35 preserves
generic retained Index data; DRV-30's stricter carrier validation requires an
independently supplied contextual role. The separately reviewed fixture correction
on `66a70878c7` then passes all ten exact native Active Nix cases. It admits
generic immutable Index bytes while every explicitly supplied executable role
still rejects their schema; malformed and namespace-use refusals remain intact.
The owning `index-tree-maintenance` gate still fails explicitly as pending.
The ordinary merge correction on `4ae7309767` passes all three ordinary contracts
and the native occurrence case. The native input and Fold cases still fail
with malformed-request errors. The owning algebra gate passes 31 Core cases,
then fails its first native case; no complete algebra qualification follows.
Independent full-diff review of the recovered `a774b69878` dependency verifies
all fifteen before and after images against the fixed composition. Integration
preserves actual Original/control retention, independent per-view selection,
strict cold refusal and the eight native cold witnesses; the recovered raw
positive separately completes its source before measuring the zero-Node fork.
The composed candidate and complete T1 floor remain unqualified.

The coherent native SDK production build passes on `dc15286e5d`. Its first
six-case regression attempt stops during test compilation, before executing any
case. A separate reviewed test-only correction on `f7db752ff2` preserves the
publication-corruption oracle and immutable-address deduplication semantics.
Fresh compilation then executes all six merge regressions: four pass and two
fail, with 721 cases outside the selection. All three ordinary contracts and
the native occurrence case pass. Both remaining native cases fail during the
Recorded revision-2 same-profile fork setup, before their behavior assertions.
An unchanged-source phase diagnostic reaches signed cold preparation and the
Commit batch's Raw acknowledgment, then refuses during later held publication;
the exact predicate remains unproven. These focused results do not replace the
failing full native suite or qualify the complete algebra gate or T1.

The bucket gate inventory retains the genuine stale-Live physical-exclusion
positive and additionally requires the independent Raw-exclusion refusal in
both `store-idempotent-put` and `index-generation-manifest`. A private gate
using only the refusal does not execute or qualify the missing positive.

The genuine stale-Live fixture on `a85b475297` now passes both owning Nix
gates: four exact `store-idempotent-put` cases and fifteen exact
`index-generation-manifest` cases, including the positive and independent Raw
refusal in each. Independent review matches all 4,982 inputs of both actual Nix
sources. Test-only whole-state corrections account for the real Raw loss fence
and conditional fresh-open capability probe; prior failed runs remain separate.
The fixture starts with empty lineage sources and does not prove clearing a
nonempty lineage set. Its separate crate build passes; shared-target Tokio test
compilation initially reuses a core artifact missing APIs present in the actual
source, so that attempt executes neither selector.

The byte-identical source timestamp refresh on the same `a85b475297` candidate
then rebuilds both actual worktree dependencies and passes both exact Tokio
physical-exclusion selectors. All 6,036 tracked inputs remain unchanged; the
earlier failed compilation and this successful execution remain separate.

A final-callback diagnostic on `4b47694659` isolates the Native input failure:
registration, issuers, configuration and registries compare equal, while the
adapter drops actual disclosure rows. The shared ordinary-row builder on
`e606ef0a2d` passes its SDK build and two pure canonicalization cases. The
no-std test import correction on `83cb88a5ef` passes mandatory compilation of
all application test targets; all 4,611 actual Nix source inputs match that clean
commit. Complete native projection, recovery composition and the current T1
floor remain unqualified; no task, milestone exit or freeze advances.

The normally composed disclosure and recovery candidate on `959f74486b`
passes its native SDK build. Separate bounded test-compilation corrections
produce an eleven-case run on `c7bf1a50fa`: both disclosure regressions and all
six owning ordinary/native merge contracts pass; the three recovery cases fail
before their maintenance assertions. The owning `algebra-merge` Nix gate on
`ed7aa2f06a` subsequently passes all 38 unique exact cases (32 Core and six SDK).
Independent review matches all 4,993 actual source inputs. These scoped passes
do not replace the earlier failing full native suite or qualify T1.

Finer opt-in tracing on `b92d3afb3d` corrects the initial location inferred for
the recovery fixture refusal: actual native registration, binding, verifier
installation and Original-retention loading all complete. Its next raw reflog
append uses a new record without a candidate identifier, which the backend
explicitly refuses. The separately reviewed test-only correction supplies the
genuinely signed commit identity as an ordinary raw selection identifier while
preserving real signing, Original checks, full previous-record matching, append
and CAS. Recovery qualification remains pending; no production factory change,
task acceptance, milestone exit or freeze follows from this diagnostic.

The shared `index-tree-maintenance` gate now names 107 exact contracts across
Core, native `std` and native Tokio inventories, including actual lookup,
publication, backfill, recovery, locality and safe-index disclosure. It retains
explicit failing qualification guards for the native DRV-12 indexed-value limit
refusal and DRV-29 multi-edit batching/resynchronization witnesses. Registration
and successful evaluation do not qualify this gate or any owning task.

The corrected raw-selector fixture on `9e20164d3a` passes its exact read-only
divergence/nonmutation case. The complete three-case recovery selection then
passes that case and fails the other two; their auxiliary-loss setup and
independent producer/current/final-ACK coverage remain unqualified. All six
exact native/structural locality cases pass separately on the same unchanged
6,047-input source. The owning locality Nix gate also passes all six exact
cases; independent comparison matches all 4,993 actual Nix source files to
`9e20164d3a`. These locality results do not qualify full recovery or the complete
maintenance gate.

The owning `derivation-memo` Nix gate passes all 28 unique exact cases on
`8f0a7887a0`, including native memo reopen and live-output collection. Independent
comparison matches all 4,993 actual Nix source files. The shared test namespace
on `ec3cdcec6e` passes compilation of all application unit and integration test
targets; this compilation check does not run those tests. Two additional native
maintenance contracts and recovery fixture corrections remain under qualification.
A separate test-only bucket namespace is reserved for verified metadata pack
paths, preserving the payload-only production placement interface. No task
checkbox, milestone exit or freeze advances.

The private CLI composition on `77358a847b` passes all three owning Nix
workflow cases, including fixed historical checkout; independent comparison
matches all 4,996 actual source files. Its separate Nextest run passes two
cases and times out during merged checkout at the unchanged 120-second limit.
The owning feature matrix passes both 628-case Core configurations, then stops
with 18 native-only import errors without `std`; its native phase is not reached.
The shared indexed-read module and re-export now require `std` under CRATE-7
and CRATE-29. The trunk `runtime-agnostic` gate passes all seven exact tests and
its compile configurations on `43c3a299e2`; all 4,614 actual source files match.
The required all-application test-target compilation on that commit stopped
after its execution handle disappeared: no build process remains and its Nix
output is unregistered. Its captured source matches all 4,614 files, but it has
no completion result. Replacement qualification remains required. Both format
checks pass, and the private CLI rebase preserves every other byte of its prior
tree.
These scoped results do not qualify the combined feature matrix or CLI task.

The corrected metadata-loss recovery fixture on `95126ca0ee` passes the
read-only case, then fails the loss/rebuild case with `Advance(Expired)`; the
final producer/current/ACK case is not reached. All 4,996 actual Nix source files
match. The whole-case duration does not identify which publication expired.
The native DRV-12 limit witness on `50dac2a8a2` passes its exact 4,096/4,097-byte
boundary, typed refusal and unchanged-publication assertions. The shared gate
now requires that exact test, bringing its inventory to 108; the explicit
DRV-29 qualification failure remains. Its first 1,024-entry batching witness
times out during initial source admission before baseline publication or the
measured maintenance operation. Solo qualification remains pending; it must
retain the same source and deadlines to distinguish concurrent host pressure
from fixture or runtime costs.
No owning task checkbox, milestone exit or freeze advances.

An isolated instrumented run of the fourth private backfill case on
`faf2f0adfa` still fails with `Expired`. It reaches both catalog ACKs and
durable reflog staging, then observes 30.803 seconds against the unchanged
30-second deadline. Within the instrumented paths, no plain-read acquisition
entry overlaps a recorded same-root native holder lifetime. These observations
do not establish the preceding uninstrumented failure's cause or exclude
unobserved descriptor lifetimes. A reviewed candidate appends the already
closed signed Commit to the final metadata run, preserving actual pack/index
durability before Commit catalog admission, all post-publication checks and
ordinary separate Commit publication for fallback and final Chunk barriers.
All four backfill cases and six publication batch cases pass on the amended
producer. Its first recovery failure and subsequent placement-isolated recovery
qualification are recorded above. No deadline or failure oracle changes.
The shared `chunk-codec` gate now additionally requires the exact native
dictionary-preload consumer witness, alongside its existing reader coverage.

The preceding completed full qualification records candidate
`21981e66f440`, which combines the reviewed immutable owner completion and
native namespace acquisition with the preceding immutable index/Memo work.
Both mandatory formatters, five immutable index/Memo/no-std checks and
application compilation pass. Application records cover 109 test executables
across 29 packages, including 72 integration targets, without executing tests.
All 5,775 tracked file images remain unchanged throughout the ten-command run;
all command log hashes are verified, and seven actual Nix check/compile inputs
match the reviewed source. Both default and keep-going current-trunk aggregates
exit 1.
The default fails `index-generation-manifest` when physical-exclusion admission
returns `Unsupported`; the complete inventory reports twelve failed gate
dependencies, listed under T-DRV-2. Its first native feature profile records
378 passing and 47 failing tests out of 425, with none ignored or filtered;
later profiles and the three mandatory native disclosure cases remain
unqualified. The `commit-order` failure returns `Expired`; the original
outcomes do not establish timing causes or a regression. The reviewed core
completion independently passes all 655 tests with zero skips and strict
Clippy/rustdoc. The native source candidate passes all 146 default tests with
zero skips and strict rustdoc; strict native Clippy remains red on 36 library
and 16 test diagnostics outside its owned files. No formal task merge,
task checkbox, milestone exit or freeze advances.

An unchanged single-thread libtest diagnostic of the same first native profile
executes the exact 425 cases: 420 pass and the same five file-backend cases
return `Unsupported`, with none ignored or filtered. All 378 original passes
remain passes; the 38 `Expired`, three `Denied` and one `Elapsed` failures do
not recur. The test body takes 738.75 seconds. All 2,754 Rust/Cargo images
match the original immutable Nix source before and after the run. This
demonstrates scheduling sensitivity without qualifying the protected Nix gate
or identifying its original contention mechanism. Terrane's feature-matrix
libtest invocations now schedule independent cases one at a time; every
configuration, internal competing-writer test, clock and deadline is retained.
Authoritative gate qualification remains pending. Retirement/restore and
destination copy activation still need complete production implementations;
the raw retirement-association and existing-registration refusals stay intact.

D-108 closes the copied-destination Pending recovery locator gap using an
additive protected staging key and the existing commit encoding. Its shared
key-separation witness passes the hermetic `bucket-key-registry` gate and
both mandatory formatters. The `bucket-file-layout` gate retains its four
original cases and now requires seven additional complete copy, history,
registration, burn, recovery and cancellation witnesses. Missing witnesses
fail explicitly; implementation and full qualification remain pending.
`bucket-key-registry` and `bucket-file-cas` also require the exact protected
staging-key witness; its native implementation remains pending qualification.

The admission candidate's corrected test observer passes all six owning tests
out of 431 declared cases; 425 cases are outside that scoped run. Strict
private rustdoc, application compilation and both mandatory formatters pass
on the corrected source. Application compilation retains metadata for
109 executables across 29 packages, including 72 integration targets, without
execution. Focused strict native Clippy still fails on inherited unused code;
it reports no owned diagnostic. Earlier passing gates used the prior observer
and do not qualify the corrected source or complete trunk floor.

The shared native writers now use the registered 16-byte temporary-name
suffix, preserving separate 32-byte operation and candidate nonces. All eight
exact `bucket-file-atomic-write` cases and both mandatory formatters pass.
Application compilation passes for that trunk source, recording 107 test
executables across 29 packages, including 70 integration targets, without
execution. Both actual Nix inputs match the two corrected writer files.
This prerequisite does not qualify the isolated copy or disclosure candidates.

The shared native creation executor now contains closed Pending durability,
artifact-descriptor synchronization and final Committed acknowledgment paths.
Only the native worker can fill their results; unit or swallowed-error success
cannot advance the producer. Its three empty-result refusal cases pass, with
366 other native cases outside that run. The native build, strict private
rustdoc, eight existing atomic-write cases, all 38 capability cases and both
mandatory formatters pass. Application compilation records 107 executables
across 29 packages, including 70 integration targets, without execution.
All four reviewed source images match the three actual Nix inputs. Original
failed module/import/diagnostic integration attempts remain preserved.
Production creator adoption, positive journal effects and strict Clippy remain
pending; the new producer entry points are unused until that adoption. This
shared prerequisite grants no collection, deletion or age authority and
advances no task checkbox or milestone freeze.

The owning registry now also requires eight actual native creation/journal
witnesses in `bucket-file-atomic-write` and an exact external journal-key
association witness in `bucket-key-registry`. Missing witnesses fail explicitly;
the preceding eight-case atomic result does not qualify these additional cases.
Registry completeness and both mandatory formatters pass. The atomic request
refuses its first missing creator case; the key request stops at the preceding
missing native staging-key case. All nine creator selectors occur in the actual
rendered check scripts, whose inner and outer AOS Bash syntax passes.
Native disclosure gate failures now emit their captured case output before
exiting, preserving the original failure status and successful execution checks.
The earlier four isolated gate failures discarded that output during sandbox
teardown; their exact failed cases remain unknown, and no cause is inferred.

A separate local disclosure diagnostic selects the original nested-occurrence
case under its original `std,send,tokio` profile. Its hermetic harness enables
test-only denial-site reporting explicitly, preserves failed output and status,
and requires the exact case to exist and execute. The first instrumented exact
Cargo invocation returns success, but interleaved diagnostic output interrupts
the ordinary checker's named status line; the harness exits with a validation
failure and discards captured output. That passing non-reproduction establishes
no cause or fix for the earlier denial. The dedicated harness now emits output
before validating its one-case summary, retaining exact discovery and filtering;
ordinary conformance checkers are unchanged. The corrected harness has passing
format, evaluation and inner/outer AOS Bash syntax checks, with no new execution
claim. This diagnostic is outside the conformance gate aggregate.

The normal native disclosure suites now apply the feature matrix's serial
case scheduling policy. Every selector, required witness, feature profile,
successful execution check and internal competing-writer case remains intact;
no clock or operation deadline changes. The original composed aggregate
captures additional `Expired` failures under its prior scheduling. This
harness change alone establishes neither their cause nor passing gates.

The original immutable private composition `65922b0704d8` finishes its
keep-going current-trunk aggregate with ten failed gate dependencies and
unchanged source. Its serial native feature profile executes 454 cases:
450 pass and four retirement/readmission paths return `Unsupported`; later
profiles do not run. Both mandatory formatters and the diff check pass.
The preceding parallel suites also preserve expiration and bounded fixture
timeout failures. These results do not qualify the changed scheduling harness.

The separate shared collector candidate `559d806ac9bb` retains completed
history dependency cuts, exact absolute root occurrences and immutable read
interpretations. Actual selected side-record inspection retains physical
preimages without marking unrelated discoveries; semantic cache hits still
record their identities. Four genuine native witnesses pass, including private
source erasure and explicit-empty interpretation refusal. Native, standard and
no-default builds, strict private rustdoc, both formatters and application test
target compilation pass. All twelve changed source images match the actual
application derivation. Strict Clippy still rejects unused interfaces awaiting
their production traversal consumers and inherited unused code. This private
candidate grants no retirement or deletion authority and advances no task.

The next private collector prerequisite `fcfecd083c8b` retains complete held
catalog data, inventory-bound detached indexes and exact protected selected
lineage receipts. Pack observations retain actual metadata without reading
pack bodies or granting elapsed-age authority. Six focused native witnesses
pass out of 460 declared cases; the remaining 454 are outside their filter.
The data-body witness arms and exercises whole, ranged and nofollow read traps,
and corrupted selected lineage is refused without submitting native effects.
Native, standard and no-default builds, strict private rustdoc and both
mandatory formatters pass. The hermetic singleton gate executes all nineteen
required cases successfully. Application qualification compiles 109 test
executables across 29 packages, including 72 integration targets, without
executing them. Both actual derivations match all eighteen frozen source
images. Strict Clippy reports twenty-eight library diagnostics, including
interfaces awaiting actual collection consumers; none are suppressed. The
common traversal and current-root retirement qualification remain in progress,
with no task merge, checkbox, milestone exit or freeze advanced.

The private native container candidate `d314e3c0bc` opens and retains the actual
pack, detached-index and protected Committed-journal descriptors through a
closed executor result. Six native mechanics cases pass, covering fourteen
journal classifications, twenty descriptor/read handoffs, four final-sync
replacements and actual cancellation exclusion. Pack bodies remain unread.
The follow-up `235b07464e` refreshes genuine producer checks after the final
bounded reads and completed effect, before acknowledgment. Its seven focused
cases pass out of 467 declared tests; a separate genuine creator regression
executes all nine selected cases successfully. Native, standard and no-default
builds, strict private rustdoc, both mandatory formatters and the diff check
pass. The hermetic singleton gate executes all nineteen required cases and
matches all thirty-five frozen source images. Strict Clippy still reports
thirty-eight library diagnostics and six test diagnostics, including interfaces
awaiting their production consumers; none are suppressed. These observations
and mechanics grant no current-root, grace, retirement or deletion authority.

A separate historical traversal diagnostic produces a real selected checkpoint
through the earlier collector, preserving its actual roots, whole lease, state
and immutable mark revisions. Its decoded marks omit the four actual I/P/G
identities and signed side record. A fresh native reopen with the corrected
walker refuses that incomplete checkpoint and leaves its selected state bytes
unchanged; lease renewal remains an actual preceding effect. Both original
executions and their exact source images are retained. Review also identifies
GC-30's independently rooted producer and manifest/dictionary attribution
cases for further scoped qualification. The common walker and fresh current-root
producer remain open, with no task merge, checkbox, milestone exit or freeze.

The private current-root composition `ca06bcd22373` uses independently verified
collection-root carriers for selected checkpoint replay and fresh traversal.
It retains the separately protected Guard record and complete current refs,
including opaque Notes and absent-name history. All four focused native cases
pass out of 487 declared tests; 483 are outside their filter. They exercise
changed refs while preserving completed cycle marks, opaque Notes and retained
history, incomplete checkpoints and stale whole leases, and conservative
retention-cutoff dominance. All frozen source images remain unchanged during
that run. The preceding attempt passes three cases and fails the fourth at its
final test mutation, which incorrectly supplies a bare Note name; the corrected
test uses the canonical ref-record key and reaches stale-observation refusal.
Both original results remain preserved. Retirement, backend grace, restore and
physical deletion remain unqualified; the full current T1 floor remains red.
No task checkbox, formal task merge, milestone exit or freeze advances.

The same current-root source passes the hermetic singleton-lease gate's nineteen
exact cases. Its actual derivation matches all 541 frozen Terrane/core, Cargo and
gate source images. Separately, the reviewed common-walker candidate
`8f519d1f94c4` passes all fourteen owning cases out of 488 declared tests; 474
are outside their filter. All twelve committed source images match the actual
compiled inventory and runtime. The witnesses retain independently rooted
producers in their own contexts, preserve certified content cuts alongside
independent attribute origins, and inspect unrelated metadata catalog claims
without private producer probes or new roots. Earlier fixture failures remain
preserved; their corrections retain source directory permissions, use actual
FastCDC boundaries and assert the genuine independent attribute witness.
The shared `gc-mark-reachability` producer now requires those fourteen exact
selectors and refuses missing cases. Registry completeness and static formatting
pass; composed runtime Nix qualification and strict lint remain pending. Initial
retirement is under separate implementation; restore and deletion remain open.

The initial-retirement composition `760b2cd126fa` passes native production
compilation and declares all ten required owning cases. Its serial runtime
executes ten of 498 declared tests: two pass and eight fail in 67.841 seconds;
488 are outside the filter. All frozen source images remain unchanged. The
eligible path fails before the intended durability checks while capturing an
absent generation whose parent directory is also absent. The reviewed fix
uses the existing exact-absence capture and retains backend I/O diagnostics.
A separate genuine creator handoff adds a distinct pack/index timestamp
witness without rewriting timestamps. Both changes await runtime qualification.
The original compile lifetime failure and runtime failures remain preserved.
Strict native Clippy remains red; no retirement, grace, restore, deletion,
task merge, milestone exit or freeze is qualified by this composition.

The corrected retirement source `febc7380da91` declares 499 native tests and
executes eleven owning cases: ten pass and one fails in 173.098 seconds; 488
remain outside the filter. The remaining fixture inspects the latest transaction
after reopen has selected a capabilities-probe update. Its corrected ordering
and the reviewed lint cleanup await requalification. Independently, all four
new native root-inventory cases pass out of 492 declared tests in 81.430 seconds,
covering current commit classes/job expiry, selected retained history,
snapshot/reopen continuity and incomplete-successor refusal. The shared
`gc-roots-complete` producer requires those four plus the previously qualified
opaque-Notes/current-root case, with exact inventory validation. Registry and
format checks pass; composed Nix gates and full T1 remain unqualified.

The private composition `079866be4bd1` passes native production compilation and
strict all-target Clippy without new suppressions. It declares 503 native tests,
including all 35 selected retirement, current-root, common-walker, root-inventory
and held-read cases; their combined runtime remains under qualification. Two
earlier preserved lint failures identify test calls to a removed byte-only
wrapper and a direct wall-clock call in the distinct-timestamp fixture. The
corrections retain exact observed reads and wait on a separate actual backend
timestamp without rewriting either pack/index timestamp. The shared
`gc-grace-window` producer requires four exact native cases covering the strict
pair-age boundary, independently newer index, enforced commit bound and actual
exclusion-before-Trash acknowledgment. Its Nix execution remains pending.
Restore, physical deletion, task merges and the complete T1 floor remain open.

The same frozen native composition subsequently passes all 35 selected cases in
372.381 seconds; 468 declared tests remain outside the filter. Strict private
rustdoc and the actual root, mark and singleton Nix gates pass all five,
fourteen and nineteen exact cases. All 572 inspected source images match each
actual derivation. Separate builds and complete runtimes pass the default
profile's 156 cases and no-default profile's 78 cases without skips. The
`std,send` library builds, but its test compilation fails because the synchronous
Rc fixture is selected by absence of Tokio alone. The original default strict
Clippy check also remains red on 63 library and 17 test diagnostics. No complete
feature-matrix or T1 claim follows from the native successes.
The focused `checks.terrane.integration.native-preownership-restore` check
requires ten exact actual restore witnesses and fails on missing cases. It is
a supplemental producer/executor check; `gc-two-phase-delete` remains pending
until actual deletion-window, ownership, physical recovery and cancellation
behavior also qualifies. Restore implementation and test-profile correction
continue in separate isolated worktrees.

The private five-file test-profile correction `0c0c108e4f24` selects actual
Rc lease fixtures only in compatible non-Send tests, preserves generic Send
clock contracts and uses the standard synchronous no-op waker. Separate complete
runtimes pass 156 default, 78 no-default, 149 `std,send`, 156 `std,surface-sdk`
and 157 `std,wasm` cases with no skips. Native strict all-target Clippy, strict
private rustdoc, both mandatory formatters and the actual singleton gate's
nineteen exact cases pass. Application qualification compiles 109 test
executables across 29 packages, including 72 integration targets, without
executing them. All 572 source images match both actual derivations and the
preserved commit. Default strict Clippy remains red on 63 library and 14 test
diagnostics; no warning is suppressed and the complete feature matrix remains
unqualified.
D-109 clarifies GC-29's privately qualified exact restoration: existing serving
placements, quarantine, other exclusions, burns, owners and selected source
lineage remain unchanged when one active binding is cleared with its eligible
rows. The native implementation acquires a genuine maintenance lease and
derives fresh current roots using a retained candidate-only metadata view;
The immutable candidate `a1b291ecc955` executes all ten native restore witnesses
with no failures in 387.038 seconds (Nextest run
`b7a6dc8f-b039-4e46-8b75-1a0b68f83409`; 503 cases outside the selection).
All 730 frozen source images remain unchanged. Genuine independent destination
activation and paired import qualify copied source history without creator
journals; the current-control, candidate-Meta physical-loss and actual restored
live-row/public-availability witnesses pass. Collector regressions, strict
profiles and final source-bound harness qualification remain in progress.
Physical deletion and the complete T1 floor remain open; this is no task merge.

The frozen composition `ff14aef673f4` passes actual Nix
`gc-grace-window` and `bucket-file-layout`, executing all four and eleven exact
cases respectively with none ignored. Both actual derivations match all 626
frozen Terrane/core, Cargo, specification and gate source images. File-layout
witnesses cover selected portable-copy closure, absent-name history, genuine
destination registration, preserved burns, activation recovery at each boundary,
interrupted source projection and retained cancellation exclusion. Neither check
qualifies restore, physical deletion or the complete T1 floor.

The opaque native effect and initialization requests expose their existing
consuming synchronous executors to `LocalFs` adapters. Their private inputs,
physical checks, result channels and durability/drop order are unchanged; Tokio
retains its owned blocking-worker dispatch. The two public-API-only examples
compile as doctests, alongside the existing compile-fail store contract. These
methods also pass strict private rustdoc. They do not supply exclusion or clock
constructors, and the full current floor and default strict lint remain
unqualified.

The composed synchronous executor reachability check on `8768bcf86a5d`
reduces both default and `std,send` strict lint failures to one library and
ten test diagnostics. It does not establish clean portable lint. Its first
public-doctest attempt fails before rustdoc on 42 missing core APIs; no example
runs. A single byte-identical core source timestamp refresh causes Cargo to
dispatch a core rebuild and select matching metadata/library artifacts. Both
public examples then pass, with all 553 frozen source images unchanged. The
verbose command reveals an inherited compiler-cache wrapper whose AOS source
provenance is unverified. This is a public-access compile result, not complete
hermetic qualification; subsequent local checks must remove that inherited
wrapper. Original failed attempts remain recorded. Actual Nix gates qualify
their own declared AOS tool closures independently.

The current floor also includes the four still-pending T1 gate obligations
`algebra-fork`, `derivation-memo`, `gc-two-phase-delete` and
`index-tree-maintenance`. The exhaustive task and exit inventory contains 65
distinct specification gates; all other names have implementations in the
reviewed composition. AD-11 places Memo and index maintenance in this milestone.
An implemented-only aggregate omitted these obligations and could not establish
T1 completion. These named failures and the separately registered ext4 workflow
now participate in the aggregate; later milestone gates remain outside it.
The registry check independently requires every T0/T1 plan gate citation to
belong to this floor. Missing implementations and the unqualified ext4 workflow
therefore prevent aggregate success.

The current floor additionally requires `checks.terrane.integration.local-sdk-checkout`:
five exact public-API witnesses for pinned ref/fixed-commit checkout, scoped
entries, registry/mode/endpoint/policy refusals, fresh authority checks and
completed-directory lifecycle. Its consuming test target remains on a private
candidate; registration supplies no runtime qualification. This local
prerequisite does not claim the broader named `sdk-checkout` gate's future
remote parity, job or extended algebra obligations, which remain ordered by
T2/T3 and the branch worklines. The CLI frontend and genuine ext4 workflow also
remain unqualified local deployment obligations.

The clean public-only five-file SDK candidate `60055ac21a` passes all ten
final checks: build, exact inventory, five native cases, strict all-target
Clippy/private rustdoc, three doctests, the strengthened Nix prerequisite,
application test-target compilation and both mandatory formatters. The final
Nextest run `cb19302f-36b1-49ce-bbe1-44fea62a6982` completes in 22.119 seconds
with none skipped. The tests drop the original repository and credentials
before reopening. Both actual Nix inputs match all 4,780 frozen snapshot
files and symlinks, including executable status, independently checked against
the final checkout. Earlier assertion-lint failures remain preserved; their
correction changes only tests. Application compilation does not execute its
test targets. Adoption and the full current floor remain pending; these scoped
results do not qualify the broad named SDK or complete task.

The current floor also requires `checks.terrane.integration.local-cli-workflow`,
with three exact separate-process witnesses for local porcelain, private
authority refusals and configured-role compatibility. The SDK, CLI and native
restore harnesses check both named discovery and passing, non-ignored execution
through the common native gate verifier. This prevents an ignored or empty
selection from qualifying a prerequisite. The CLI target remains on its private
candidate; its registration does not supply runtime or ext4 qualification.

The frozen pre-ownership restore candidate also passes all 35 collector
regressions in 331.089 seconds, alongside its ten owning cases and actual
ten-case Nix prerequisite. The final clean candidate `f460c9b07ac4` passes
fresh native, default and
`std,send` strict Clippy, private rustdoc, both formatters and strengthened Nix
qualification. Both actual Nix inputs match all 732 frozen scoped images; all
69 evidence artifacts are independently verified. Earlier lint failures remain
recorded. Genuine elapsed-D qualification, durable local deletion ownership,
owned absence recovery and cancellation remain production prerequisites.
Codec-valid claimed-owner refusal cases do not establish those producers.

The corrected CLI candidate `d24fa88f06` passes its actual three-case Nix
prerequisite, strict Clippy/private rustdoc and both mandatory formatters.
All 785 scoped images match the actual immutable input. An unchanged-source
native confirmation passes three of three cases in 96.490 seconds (run
`f1bd3aee-0ad2-4772-a9a1-8fa83bf9fe1b`), with the original 120-second limit.
The preceding two-pass/one-timeout run remains recorded; these outcomes do
not establish its cause. The private combined candidate `704e51146dee`
passes both mandatory formatters with all 5,845 tracked images unchanged.
Its actual current-trunk aggregate exits 1 at the named `algebra-fork`
pending requirement, ALG-32. No task merge or checkbox follows.

Full-D local ownership needs renewal while retaining the genuine namespace
and control holder: D is at least G and G exceeds C. Ordinary renewal would
reacquire its retained locks, and a final check captured before renewal still
uses the old expiry. `checks.terrane.integration.native-held-lease-renewal`
requires six exact positive/refusal/durability/clock/refresh/cancellation cases
for this prerequisite. Registration does not implement it. The forthcoming
ownership slice ends at genuine durable Invalidated after all three journals
become DeleteOwned; unlink, recovery, cancellation and owned restore remain
separate producers. No duration, clock contract or local-v1 bytes change.

The test-only collector clock now supports explicit real-time progression and
Tokio sleep on the same retained instance. Existing manual sampling and
unsupported sleep remain the default. All five selected native clock
regressions pass, including three new timer/retention/regression/cancellation
cases. `checks.terrane.integration.native-collector-clock` requires exact
discovery and non-ignored execution of those three cases.
`checks.terrane.integration.native-local-first-ownership` requires six exact
full-D/renewal/incarnation/poisoning/partial-ownership/current-authority cases.
Its tests and production producer remain pending; registration must refuse
missing selectors rather than qualify an empty run. This shared fixture
prerequisite proves no deletion, recovery or cancellation authority and advances
no task checkbox or milestone freeze.
The first qualification exposed existing fixture feature mismatches and direct
host-clock calls rejected by workspace lints. The helper now samples elapsed
time through the existing native Clock binding; local filesystem fixtures
remain in their non-Send lane and native lease fault selectors require Tokio.
Original failures remain recorded, and no lint is suppressed by this correction.

The shared lease publisher now requires a closed native acknowledgment after
exact canonical selected slot/transaction/snapshot/pointer verification and
same-descriptor file and required-directory synchronization. The worker refreshes
actual clock, controls and physical preimages after its final sync before filling
the private receiver; no-op effect success cannot acknowledge publication. The
existing singleton gate executes all nineteen cases successfully, and the native
build, strict private rustdoc and both mandatory formatters pass. Its original
exhaustive test-phase compile failure remains preserved separately. This shared
mechanic does not implement held renewal, elapsed-D ownership or reclamation.
The lease handoff also retains the separately protected selected Guard record
through every queued effect; byte-only validation before dispatch is insufficient
under D-79. Strict trunk Clippy still reports existing unused production
components; no diagnostic is suppressed. The owning held-renewal matrix remains
responsible for actual queued Guard replacement, missing acknowledgment and
cancellation witnesses before this prerequisite qualifies. The crate-private
control receipt can retain its same acquired native exclusions and exact original
observations for renewal without reacquiring the already-held control lock;
cloning neither refreshes authority nor creates a new physical receipt.

The shared checked Guard/ref publisher also requires its own closed native
durability acknowledgment. Its private factory binds the exact whole successor,
selected slot, transaction, snapshot, pointer and protected proof records to
the actual checked mutation. The native worker retains the initial selected
Guard and source-lineage physical observations alongside existing Original
controls, synchronizes exact metadata on retained nofollow descriptors and
required directories, and refreshes current controls after a queued handoff
before the actual sync. Unit success or swallowed native failure cannot fill
the private result channel. `checks.terrane.integration.native-checked-mutation-publication`
requires six exact genuine repository cases for success, missing acknowledgment,
actual sync failures, replaced records, cancellation and queued directory sync.
Lease selection and its private acknowledgment remain independently required.
This prerequisite proves neither full-D ownership nor complete ALG-32 publication;
its owning witnesses and regressions must pass before it is qualified. The first
test compilation's incorrect epoch field and unconditional test-only path import
remain recorded and are corrected directly, without suppressing workspace lints.

The acknowledgment's six native and owning Nix cases, ref ordering, nineteen
lease cases, three collector-clock cases, private rustdoc, default/Send builds
and application test-target compilation pass. Full trunk qualification remains
red. Its bucket CAS selector exposed the missing D-108 protected ACTIVATION
reader case, restored with exact-key and unsafe-mode refusal coverage. The
package test run also scheduled hundreds of filesystem cases despite a
two-core builder allocation and reported expiry and timeout failures; package
Nextest now uses the existing bounded thread option without changing deadlines.
Original failures remain recorded, including unsupported legacy retirement
fixtures. Neither these prerequisites nor a focused pass closes a T1 task.
With the bounded package setting, the full native profile runs 383 cases:
374 pass and nine fail, with no skipped cases. Six failures concern legacy
retirement/copy fixtures; three multiwriter cases exceed the unchanged
30-second publication bound. The full package and aggregate checks still fail.
Bucket CAS now passes, while bucket atomic-write lacks its actual creation
witness on the trunk; that producer and case remain in the private composition.
Both mandatory formatters pass. The retained-request factory now freshly
authenticates each exact token once and retains its opaque verified data.
Every later boundary reselects current issuer rows and reevaluates time,
caveats, locality, epoch and the unchanged original deadline. Independent
current ACL, Guard, source, Original and physical checks remain required.
All seven native request cases and all seven exact owning Nix cases pass;
the six native and owning acknowledgment regressions also pass. Actual Nix
inputs match all 4,522 frozen source files and all six changed code/gate files.
Default/Send builds, strict private rustdoc, registry, ref-advance ordering
and both mandatory formatters pass. Original compilation and incorrect
Denied-source assertions remain recorded; denials still expose no diagnostic
cause. Strict native Clippy retains the existing 34 library and 12 test errors.
The initial misspelled ref-ordering check refused an absent attribute; the
correct registered gate passes without changing its selector inventory.

The subsequent full package runs 884 cases: 876 pass, eight fail and none
are skipped. Its exact failed-selector inventory contains the same six
legacy retirement/copy fixtures and two explicit multiwriter expiries.
The isolated native three-case sample likewise has two expiry failures;
its rebase case passes. These are separate scopes, and neither establishes
an expiry cause or deadline fix. The aggregate remains red; four unfinished
specification gates stay pending. No task checkbox or milestone freeze advances.
The private first-ownership producer and actual native test targets now compile.
Its original missing/feature-specific fixture imports are corrected directly;
runtime qualification is still red, with two 120-second ownership timeouts
and an early-wait observer timeout recorded so far. Full-D ownership,
recovery, unlink and cancellation remain unqualified.

The checked mutation now synchronizes its actual final writes, completed
projection repairs/removals, newly selected log and genuine current Original
rows, plus unique required directories. Every complete input refresh and current
operation check remains required. The six original acknowledgment fixtures are
unchanged; six additional fixtures independently derive the expected sync paths
and exercise actual queued file/directory faults. All twelve native cases and
both six-case owning Nix checks pass. Ref-advance ordering, registry,
default/Send builds, strict private rustdoc and both mandatory formatters pass;
strict native Clippy retains the same 34 library and 12 test errors without
suppression. The two original new cache-oracle failures identified an incorrect
test handoff and remain preserved with their corrected runs.

The subsequent full package executes 890 cases: 884 pass, six fail and none
are skipped. Its remaining failure inventory contains the same six legacy
retirement/copy fixtures; all three unchanged multiwriter cases pass both the
isolated sample and this package run. These observations do not establish a
general expiry fix. Actual package inputs match all eighteen changed code/gate
images at that run; subsequent changes add documentation only. The aggregate
still fails, and the four unfinished specification gates remain pending.
The private first-ownership matrix finishes with three failures and three
120-second timeouts. Corrected fixtures and the exact lease synchronization
proposal remain unqualified. Temporary dispatch traces observe real queue and
worker entry, initial current checks, and repeated complete input refreshes;
they do not establish a timing cause and are removed from production sources.
No formal task merge, checkbox, milestone exit or freeze advances.

The existing private cold-fork source candidate retains its original commit
`78eb15c7f6` and current prerequisite composition for review and adaptation.
`checks.terrane.integration.native-cold-fork-source` requires its six exact
non-ignored native cases; registration alone does not qualify them. The shared
selected-lineage reader retains actual protected metadata/body and checks the
selected digest and source name before and after observation. Its receipt is
read data, not publication authority. End-to-end fork publication with no
TreeNode reads/decodes and source-preserving collection remain ALG-32
prerequisites; the broad `algebra-fork` gate stays pending.
The same focused integration check now additionally requires five exact public
publication/interpretation cases and one route-lifetime regression, for twelve
selectors total. The public fork case measures preparation through final
publication. Missing selectors fail explicitly until the isolated production
draft and shared preparation hook are qualified. Source-preserving collection
and the full `algebra-fork` gate remain separate obligations.
The isolated cold-fork candidate compiles and discovers all twelve required
cases. Its first runtime witness initially refuses in configuration snapshot
comparison; a finite test-only trace separates this from setup and later profile
checks. The corrected source uses the actual held Guard's independently retained
Original state, including disclosure roles and public trust, while preserving
protected snapshot, lineage, source, Original and full-profile checks. The original
first case passes in 9.33 seconds after removing the diagnostic instrumentation.
All twelve exact cases subsequently pass with zero ignored on the same frozen
source, including genuine public fork publication with zero observed TreeNode
gets, puts and validator decodes. Strict Clippy then identifies a large private
enum and a complex tuple type; their reviewed representation repair preserves
the qualification predicates. The successor passes default and Send Clippy and
rustdoc but initially fails native Clippy on two fixture lock panics. Fallible
fixture error propagation is under final qualification; the twelve-case owning
check must pass on that final source. Source-preserving collection and the full
`algebra-fork` gate remain pending.
The final bounded successor `3df0c2b7c5` passes the twelve-case owning Nix check,
strict three-configuration Clippy/private rustdoc and both formatters. Independent
review confirms all twelve positive, nonignored executions and all 4,867 actual
Nix input files. The public fork retains zero observed TreeNode gets, puts and
validator decodes through durable publication. This source is composed locally;
the actual older selected missing-context fallback and source-preserving
collection witnesses, full trunk gates and formal task merge remain open.

The shared Guard-carry publication consumer now retains private old-selector
and fresh-lineage bytes, verifies exact selected associations, installs each
immutable output before selected publication, and includes it in the actual
native durability seal. Foreign source Originals remain independent of the
current destination backend registration; fresh lineage preserves its exact
Original and changes only its Guard digest. Existing Guard producers still
supply an empty carry list. On these frozen shared bytes, all six exact native
checked-publication acknowledgment regressions, application test-target
compilation and required formatting pass. All 4,557 hermetic input files match
independent review. Strict default Clippy retains the prior 37 library and 22
library-test errors; later profiles and rustdoc are unqualified. The real
preservation producer, its positive/refusal witnesses and full trunk gates
remain pending. This prerequisite closes no task or milestone.

The ordinary missing-placement prerequisite now retains actual absent canonical
artifact observations and ancestor identities through Raw publication, verifies
present counterparts, and permits only an exact old Live-row replacement with a
fresh pack identity. Corrupt, unavailable, excluded and quarantined evidence
cannot become absence. The actual Raw executor owns the durability result;
no-op success or swallowed synchronization cannot populate its receiver.
Conservative loss-generation advancement and source clearing remain unchanged.
On the frozen shared source, upload verification, all six checked-publication
ACK regressions, application test-target compilation and both formatters pass.
All 4,559 actual hermetic input files match independent review. Strict default
Clippy retains exactly the prior 37 library and 22 library-test diagnostics;
later profiles and docs remain unexecuted. The original added unused-wrapper
diagnostic and incorrect ACK registry lookup are preserved before correction.
The existing physical-exclusion idempotence fixture still returns Unsupported
because it changes retirement associations through ordinary Raw publication;
its remaining two selectors were unexecuted. Separate review finds that the
trunk's stage-container path still lacks the genuine Pending/Committed creator
producer. Its exact private implementation and seven actual repair witnesses
are under review; their creator assertions remain mandatory. These bounded
results qualify no complete repair, rebuild, task merge or milestone exit.

The actual retained container creator now replaces direct artifact staging:
both members are preflighted, missing members consume native Pending, descriptor
seal and Committed acknowledgments, and equal present members retain their old
journals without acquiring creator authority. On these exact shared bytes,
upload verification, six checked-publication ACK cases, application compilation
and both formatters pass; all 4,560 actual hermetic input files match independent
review. Real factory use removes inherited dead-code diagnostics, while strict
default Clippy still fails with 24 library and 17 library-test errors. Later
profiles/docs and the complete creator fault matrix remain unqualified.
Two focused integration checks now require seven actual missing-placement
witnesses and four held Guard-carry witnesses. Missing selectors fail discovery;
registry presence establishes no runtime result. Signed Original/current checks,
actual creator receipts, original absence/ancestor handoffs and real inner Raw
sync faults are mandatory. The existing idempotence failure and complete
milestone floor remain open.
Registry completeness and both required formatters pass for the new check
definitions; neither missing-selector inventory is recorded as passing.
The shared collector gate runner now checks each original execution report
with the existing native checker: the exact named case must pass with nonzero
passes and zero ignored tests before the gate writes its result. Required
selectors and feature profiles stay fixed. Registry completeness and both
mandatory formatters pass; this runner change establishes no collector runtime
result on the incomplete trunk.
The subsequent coherent private repair source `35879ccb5cff` passes all seven
exact missing-placement cases and their 19 finite fixtures. Fresh placement,
actual corruption/quarantine/unavailability refusals, original absence/ancestor
handoffs and all eight Raw acknowledgment/fault modes execute successfully.
Strict default, Send and native Clippy with private docs, application test-target
compilation and both formatters pass. Independent review binds all three actual
derivations to their 4,897 included files and verifies the unchanged 5,951
tracked images. The correction preserves genuine creator effects and requires
the exact corrupted Pack or Index identity. Native rebuild, incremental
maintenance, complete trunk qualification and formal task merges remain open.

The corrected private Guard-carry source `f45d8ee00e9b` passes its four exact
owning cases and thirteen cold-fork regressions, with zero ignored tests.
Strict default, Send and native Clippy/private docs, application compilation
and both mandatory formatters pass. Independent review binds the original
reports to 4,909 actual Nix input files and the unchanged 5,963 tracked images.
The foreign-dependency fixture forks its local source; cold reuse of its
imported head and the raw-source full-admission fallback remain unqualified.
The subsequent corrected private imported-source composition `9d5cd28c33ae`
passes its exact owning retirement/cold-fork case and all nine source-carry
and thirteen cold-fork regressions, with zero ignored tests. The owning case
executes genuine imported publication, distinct native-acknowledged retirements
through the exact seeded orphan, complete per-step lineage retention and a
calibrated zero-TreeNode fork of the same local head with foreign used views.
Strict default, Send and native Clippy/private docs, application compilation
and both mandatory formatters pass. Independent review verifies every original
terminal result and evidence seal, all 4,907 included files in each of five
actual derivations, and all 5,961 unchanged tracked hashes, modes and mtimes.
The earlier xattr and first-eligible-orphan failures remain preserved. This
bounded composition qualifies that imported-used-view case; true foreign heads,
multiple owners, the separate raw-source requalification path, physical deletion
and complete ALG-32/current-trunk qualification remain open.
The first coherent trunk Original prerequisite preserves ordinary protected
acquisition and adds exact same-holder read/recheck plumbing. Its frozen source
`7433f151d7` compiles all default, Send and native test targets and passes four
exact existing Original/consumed-context regressions with zero ignored cases.
Both mandatory formatters pass, and independent review verifies every original
terminal result and all 5,618 unchanged tracked images.
The next trunk slice installs the genuine receipt only after the native held
factory checks the consumed controls. Candidate publication rechecks its
installed Original under that same receipt, then repeats current selection and
time checks before the existing native dispatch. Frozen `68df745fb9` compiles
default, Send and native test targets; passes the four Original/consumed-context
regressions plus genuine ordered publication/reopen, rollback and final
registration-refusal cases; and passes both mandatory formatters. All seven
cases have exact named successes and zero ignored cases. Independent review
verifies every one of twelve terminal results and 5,620 unchanged tracked
images. The actual positive paths close native acknowledgment before their
independent durable assertions. Imported/per-view factory completion, physical
deletion, the complete collector and ALG-32 remain unqualified.
The next trunk slice implements ordinary read-only immutable index loading,
address and contextual physical checks, independent canonical namespace
reconstruction and exhaustive owner/primary/route/gap relationship verification.
Its supported executable profile is explicitly property 3, attribute 2 and
tree 1; unsupported active attribute-1 input refuses before storage reads.
This provides data preparation, not current authorization or completed history.
Frozen `90d2b2c474` passes the seven exact non-ignored
`integration.native-index-loading` cases, Core no-std and strict Core all-target
Clippy/private rustdoc. Native profile quality stops in the default profile on
unused incomplete paths and two concrete lint findings; later profiles and its
application, registry and formatting suffix are unrun. Independent review verifies
all preserved artifacts, 4,578 actual source inputs for each source-bound phase
and 5,632 unchanged tracked images. The original pre-build metadata-driver failure
is preserved separately.
A separate two-file correction uses `Option::and` for the same held-only
retained-control selection and the standard no-op waker for the non-Send lease
fixture. Frozen `d4f753f08a` compiles default, Send and native test targets, then
passes seven index cases, seven actual Original/current/consumed cases and the
non-Send lease case in their supported profiles, with exact discovery and zero
ignored cases. Application compilation, registry completeness and both mandatory
formatters pass. The full current-milestone aggregate exits 1 at the explicitly
pending `algebra-fork` gate, ALG-32. Independent review verifies all ninety
preserved artifacts, both source-bound phases' 4,578 actual inputs and all 5,632
unchanged tracked images. The original wrong-profile discovery failure is retained;
its correction changes the harness only. Incomplete-path lint diagnostics are
not suppressed, and no full native quality, task, cold-factory or T1 exit claim
follows from this prerequisite.
The trunk prerequisite retains actual staging controls from metadata creation
through final publication and completes Legacy history only after every signed
requirement, Original and historical context verifies. Contextual Raw durability
retains the actual closed Original scopes used by its submitted effect. Frozen
`1237c4f421` passes all nineteen exact cases: five Legacy completions, six native
metadata-batch groups, seven retained-control regressions and the non-Send lease
case. Discovery has zero ignored cases; default, Send and native test compilation
also passes. The corrected Unsupported mapping retains the actual native error;
Denied retains STORE-30's mandatory absence of diagnostic detail. The deadline
fixture checks the actual retained clock and worker refusal. Malformed Memo data
reaches the partial-upload schema refusal; Commit reoffers remain denied.
Core no-std passes. Strict profile quality stops in default on unused imports and
incomplete interfaces, with 24 library and 16 test diagnostics; later profiles
and private docs remain unrun, with no suppression. Independent review verifies
all 95 preserved artifacts, three derivations' 4,590 actual inputs and all 5,644
unchanged source images. A separate qualification of the same frozen source
passes application compilation (107 test executables, 29 packages and 70
integration targets; no execution), registry completeness and both formatters.
Its current-milestone aggregate fails explicitly at pending `algebra-fork`,
ALG-32. Independent review verifies its 75 preserved artifacts and actual source
binding. The earlier failed runs remain preserved. No formal task merge,
checkbox, exit gate or freeze advances.

The trunk now composes retained separate Source requalification with native cold
publication for the explicitly supported Legacy, empty-required-index profile.
The cold coordinator retains the same selected source and destination exclusions
through real publication acknowledgment. A reviewed lifetime correction separates
the coordinator borrow from its held resources without changing publication
ordering. Frozen `5447f3642c` compiles the native test target and passes all six
existing exact metadata-batch groups. Independent review verifies all 34
preserved artifacts, 4,597 actual derivation inputs and 5,651 unchanged source
images. The original lifetime compilation failure remains preserved. This is
compilation and regression evidence; the new Source/cold owning witnesses,
Active completion and complete ALG-32 remain unqualified.

The focused separate-source requalification check is registered with twelve
exact completion/refusal selectors; registry-complete and both required
formatters pass. Its first private native compilation stops on two child-module
path locators before discovery or execution. A locator-only correction is
reviewed; no source-completion or whole ALG-32 result is claimed.
After the locator and borrowed-fixture corrections, the private source
`5eb449d15e81` compiles and discovers all twelve exact selectors among 642
native tests. Raw full admission, older-lineage requalification followed by a
separate zero-Node fork, and unchanged-context refusal pass. The last case
requires exactly one actual root-directory sync, zero publication acknowledgments
and the original complete state, source, log, incarnation and control assertions.
The fourth case passes its first ACL denial and zero-ack assertions, then fails
because it expects zero filesystem effects and observes one. Its later state
assertions, five remaining refusal subcases, eight remaining selectors and all
dependent checks are unrun. Independent review verifies all twenty preserved
artifacts, 4,917 actual Nix input images and 5,971 unchanged tracked hashes,
modes and mtimes. The exact refusal path remains under review; this result
does not qualify the twelve-case gate or advance ALG-32.
The later private source `a774b698788b` qualifies all twelve owning source
requalification cases, thirteen cold-fork regressions and four Guard regressions,
each exactly discovered among 642 tests with named successes and zero ignored
cases. The final required-index refusal reaches its real unavailable auxiliary
pack read, retains the exact primary Node error, performs no publication
acknowledgment, requires only the actual root-directory sync, and passes the
complete original unchanged-state/source/control assertions. Strict all-target
Clippy and private rustdoc pass for default, Send and native profiles; application
compilation and both mandatory formatters pass. Independent review verifies all
78 original artifacts, all five derivations' 4,917 actual source inputs and all
5,971 unchanged tracked hashes, modes and mtimes. Earlier failed attempts remain
preserved. The foreign-dependency Guard case still forks the local source;
imported-head reuse, source-preserving retirement, composed trunk qualification
and complete ALG-32 remain separate obligations. This is no formal task merge.

The focused native graft-locality check now requires three actual publication
cases and three structural cases, with exact discovery and non-ignored
execution checks. Its private producer selects affected immutable graft entries
from a separately prepared reverse map; the full preparation traversal remains
explicitly charged. Exhaustive canonical-output comparison stays outside the
measured maintenance. The new witnesses are committed but unexecuted; registry
presence does not qualify DRV-29 or complete incremental maintenance.
The first owning attempt stops at a test-helper lifetime error, before discovery
or execution. Its exact signature correction preserves the constructor and all
oracles. The corrected attempt discovers 620 tests, then its first required
native case returns `Advance(Expired)` in 46.11 seconds; the other five cases
and all later checks remain unrun. The actual commit timer starts after the
preparation baseline, so moving fixture `begin` alone would not establish an
expiry fix. Original reports remain preserved. A later actual-put trace finds
seven new placements and three verified existing objects: the puts total
28.43 seconds, including 24.74 seconds in catalog publication groups. The
seventh catalog publication completes before the unchanged next time check
returns `Advance(Expired)`; no selected-ref acknowledgment follows. These
intervals identify groups, not a particular syscall or a proven cause.
A trunk prerequisite now coalesces only wholly equal captured physical
predicates, preserving distinct policies, descriptors, ancestry, bytes and
incarnations. Frozen `07929d45e2` compiles default, Send and native test targets,
discovers the exact cases and passes four actual-held capture cases plus four
existing native physical-fault/exclusion regressions with zero ignored cases.
Both mandatory formatters pass. Independent review verifies all fourteen
terminal results and 5,620 unchanged tracked images. The original fixture
visibility failure is preserved. No measured speedup, expiry fix, DRV-29 gate
or task completion follows until the owning locality cases are qualified.
The isolated writer adopts the same coalescing algorithm while preserving its
additional pair predicates and executor operations. Frozen `9a29ff12cc32`
discovers all six owning selectors among 624 native tests, then the first
actual publication case returns `Advance(Expired)` in 40.85 seconds. The other
five cases and all dependent checks remain unrun. Independent review verifies
all 5,975 sealed content artifacts, 4,904 actual Nix input images and 5,958
unchanged tracked byte/executable-mode images. The earlier predicate passes
remain scoped to the trunk prerequisite; no speedup or expiry fix is established.

The test-only bucket observer records actual typed Node/Commit get and put
attempts before catalog lookup, admission or deduplication. The same per-bucket
observer follows clones and held adapters and can attach to the actual metadata
validator's Node decoder. Three genuine native calibration cases pass: cloned
and held reads, missing Node reads without decoding, and deduplicated puts.
`checks.terrane.integration.native-content-observation` requires those exact
non-ignored cases. These counters do not infer physical pack byte ranges or
count later core tree decoders; complete cold-fork and ALG-32 work remains open.

The reviewed concrete ext4 VM harness is now adopted as a shared prerequisite.
It uses the checked release package in the existing source-built headless VM
framework, verifies the actual ext4 filesystem, and checks separate-process
init, directory commits, fork, merge, registered and historical checkouts,
reopen and unchanged persisted credentials. The old failing placeholder is
replaced; package checks remain enabled. Previous qualification stopped at
failing package tests before the VM booted. No successful VM artifact exists;
the current combined implementation still requires genuine package and ext4
qualification before T1 can exit.

The preceding completed full qualification records candidate
`15540ef204ec`, which combines reviewed source discovery, immutable lookup,
repeatable I/P/G maintenance, separate verifier/preparation work, common Memo
replay, structural Memo/Node metadata validation and native immutable index
loading and selected immutable Memo replay. Both owning checks and mandatory
formatters pass; the preceding seven Memo/Node/index/no-std checks retain their
recorded source
qualification. The application check records compilation of 109 test
executables across 29 packages, including 72 integration targets, without
executing tests. The reviewed core components pass 650 tests with zero skips.
Its default and keep-going
current-trunk aggregates both exit 1; the latter reports eleven failed gate
dependencies, listed under T-DRV-2. Its observed native feature suite records
396 passing and 25 failing tests out of 421, with none ignored or filtered;
later profiles remain unqualified.
An unchanged single-thread Nextest diagnostic of the first native profile
on the earlier `1ce3dbe9f62a` candidate executes all 409 tests: 404 pass and
five fail with `Unsupported`, with zero skips. No unexpected `Expired`,
`Elapsed` or `Denied` failure occurs in that
invocation. Different runners and scheduling conditions prevent attributing
the earlier failures to a cause; the mandatory aggregate remains red.
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

The native index feature boundary on private `066d12c9f5` passes all 76
portable and 77 WebAssembly tests with zero skips. Two native-only constructor
tests retain their bodies behind `std`; both compile and pass in the native
SDK profile. Its compiled inventory contains 735 tests; the full native suite
and feature matrix have not been rerun. The unchanged DRV-29 fixture on
`2857045eac` completes genuine source preparation, then refuses baseline
catalog publication at the existing 30-second writer deadline. Its attempted
generation installs 232 new index shards; incremental measurement and the
independent maintenance oracle are not reached. An isolated production
optimization is in progress; all normative native physical/current checks
and the existing deadlines remain qualification requirements. The later scoped
Raw review below explicitly revises the stronger intermediate sampling promise.
The owning `algebra-fork` registration now requires twelve exact native witnesses
and the separate cold-source, full requalification, source-preservation and
imported-source-preservation checks. Registry completeness and both formatters
pass; the owning runtime qualification remains pending. Gate Cargo jobs now
follow `NIX_BUILD_CORES` so explicit build-core limits also bound compilation.
The isolated `68766654c2` SDK build and actual compiled inventory pass with all
twelve owning cases present and none ignored. Its first exact native execution
passes ten cases and times out in the two new source-record/log-incarnation
witnesses at their unchanged 120-second deadlines. Review identifies an
observation adapter retaining its cloned namespace exclusion after the holder
is dropped, blocking the subsequent fork. The separate `062c7b40e2` fixture
correction drops that adapter before the holder; no production behavior,
incarnation assertion or deadline changes. Its separately frozen replacement
executes all twelve owning cases successfully in 138.261 seconds, with no ignored
selected tests and unchanged 120-second case deadlines. The original two
timeouts remain preserved. The owning Nix gate exits 1 at its mandatory
cold-source prerequisite: eleven exact cases pass, then the older-lineage
witness rejects the acknowledged logical change keys in 15.00 seconds. The
final thirteenth case, other three prerequisites and owning runtime are not
qualified. Independent review matches all 4,996 actual immutable source files
with the clean candidate. Canonical branch publication requires the destination
record, `CAPABILITIES` inventory insertion and selected-history update; the
fixture's ref-prefix-only assertion incorrectly excludes the latter two.
The separate test-only `015467114e` correction reconstructs the independently
selected prior snapshot, checks every exact predecessor edge, and compares all
three complete logical changes and the full resulting state. It retains source
record, log, Guard, lineage and Original bytes and incarnations, as well as the
zero-Node, root, parent and signing assertions. Its repaired case passes in
15.439 seconds; the complete thirteen-case cold-source prerequisite passes in
156.174 seconds and all twelve owning cases pass in 148.565 seconds at unchanged
deadlines. The original three-file capture remains scoped to those files;
complete 6,051-input source and compiled-binary captures are added during the
prerequisite run and before the owning run, then verified unchanged at completion.
Mandatory Nix qualification remains open; no prerequisite is waived and these
local passes close no task.
No task checkbox, milestone exit or freeze advances.

The isolated retained catalog cohort passes six focused real-worker tests in
its frozen Tokio invocation: complete native acknowledgment, callback-only
refusal, whole-byte change and expiry between primitives, partial rename
failure, and lock retention after waiter cancellation. The subsequent sealed
native SDK candidate `7bd19e5edb` includes the exact unchanged five-file
`2857045eac` fixture. Its first 1,024-entry ordinary case fails after 63.554
seconds when baseline publication returns STORE-30's `Denied`. The unchanged
30-second writer budget remains in force, but this uninstrumented original
run establishes neither expiry nor the duration of individual phases.
All 3,251 captured inputs remain unchanged; baseline output, measured
maintenance and independent oracles are not reached. The full-upfront cohort
does not establish a throughput fix or DRV-29 qualification.
The separate same-source diagnostic locates the refusal in the final native
Raw publication acknowledgment after all 232 shards and the generation manifest
are installed. It records no explicit expiry result and does not reach baseline
output or the measured maintenance oracle. The bounded eight-install candidate
`834dce9018` retains per-primitive checks, native acknowledgments and actual target
recapture between batches. Its unchanged 1,024-entry ordinary case still returns
`Denied` in that final acknowledgment, after 55.015 seconds for the whole case;
neither that duration nor earlier phase entry establishes a throughput fix.
All 3,251 captured inputs remain unchanged through each original invocation.
Its selected native regression run passes 79 of 80 cases, with zero ignored
selected cases; the existing Original/current/producer/final-ACK recovery witness
times out at the unchanged 120-second deadline. The native creation case now
observes the real final Raw acknowledgment explicitly and passes without ignoring
callbacks or weakening its order assertions. Strict library Clippy reports the
existing admission argument grouping; strict all-target Clippy additionally
reports duplicate test-fixture inclusion and the independent source-oracle
conditional. No owning task gate, full native suite or complete T1 floor is
qualified. The final `2fed289ff4` changes only a wrapper description after the
recorded executions. Further diagnostics and implementation must retain every
original output, acknowledgment and deadline. The prospective Raw-only
installation refinement may defer repeated whole-body reads of an unrelated,
genuinely new immutable output between exhaustive cohort boundaries. Its private
producer must independently exclude every consumed present and absent input,
preexisting or repair payload, mutable/control record, pack container and
unclassified or conflicting role. Eligibility follows actual no-replace
installation and physical rebind, never a caller claim or future synchronization
scope. Every current staging/target body and physical binding, consumed input,
namespace exclusion and deadline remains checked around the actual primitives.
Complete initial/final cohort checks, native receipts, target recapture and full
verification before the publication commit slot remain mandatory. Unclassified
callers retain complete checks. Persistent prior-output changes must refuse
before publication; unrelated transient changes restored before an exhaustive
boundary may be unobserved, and refusal precedence or harmless attempted effects
may differ. This scoped promise adjustment authorizes no weaker source checks,
successful partial receipt, extended deadline or post-commit-only verification;
its producer, fault, cancellation and boundary witnesses remain pending.

The isolated `d4f4355fef` diagnostic candidate adds opt-in test-only refusal-site
observations around the original refresh and synchronization results. Its
deadline diagnostic reports the rejecting predicate's existing clock sample;
no clock read, check, returned failure or deadline is changed. Review verifies
the same ordered check calls in all four instrumented existing files. Its
original traced 1,024-entry case fails in 58.218 seconds, with all 3,252 inputs
unchanged. The original rejecting deadline predicate now explicitly reports
`Expired` at 30.002351228 seconds against the unchanged 30-second bound. It fails
the final current refresh after syncing an actual Original bootstrap record,
inside Raw output synchronization; public STORE-30 reporting remains `Denied`
with no exposed source. Baseline output, measured maintenance and independent
oracles remain unreached. The isolated `e43bf27e90` reserves each whole-read
buffer's bounded capacity before the same fresh read, preserving every
physical/current check and proper allocation failure. Its unchanged case fails
in 73.086 seconds, with all 3,252 inputs unchanged. The final Raw acknowledgment
now completes at 23.814052259 seconds within its Raw scope. The interval from
durable-staging completion to candidate-history completion takes 20.794290381
seconds. It includes selecting the current publication, candidate-input equality,
owner-reference revalidation and genuine history completion; their individual
costs remain unmeasured. After that interval,
the original ref deadline explicitly rejects 47.685825172 seconds against the
same 30-second bound. Baseline output, measured maintenance and independent
oracles remain unreached. Its original native regression selection finishes
with 79 passed and one timed out out of 80 in 267.604 seconds; the same
Original/current/producer/final-ACK recovery case reaches the unchanged
120-second timeout. Strict library Clippy reports only the existing admission
argument grouping; all-target Clippy additionally reports duplicate fixture
inclusion and the independent source-oracle conditional. All 3,252 inputs remain
unchanged through each original invocation. This scoped progress establishes
no throughput or DRV-29 success.
The separate `4b5d80d0dd` quality
composition groups admission's owned inputs, shares the genuine existing
backfill fixture through a test-only import, and preserves the source oracle's
short-circuit order in an equivalent let-chain. Independent review verifies
the unchanged admission validation/effect tail and complete fixture bodies.
The private `2c1c723412` composition combines these reviewed corrections with
the catalog candidate and passes its native SDK build, strict library Clippy
and strict all-target Clippy. Independent review matches all 3,252 captured
inputs against the sealed commit for each original invocation. Application
test-target compilation, owning gates and full native qualification remain
open; these edits close no task.

The separate `d352aa412d` adds only test-process-clock boundaries after durable
staging. Removing its six new statements restores the prior selected-publication
file byte for byte, including every authority clock sample and check. Its
unchanged 1,024-entry case fails in 57.003 seconds before those boundaries: the
original Raw acknowledgment deadline rejects 30.001059197 seconds against
30 seconds before synchronizing `objects/index/21/235.idx`. All 3,252 captured
inputs remain unchanged. No acknowledgment return, post-stage timings, baseline
output, measured maintenance or independent oracles are reached. The new run
does not measure the individual costs of the earlier candidate's post-stage
interval or establish DRV-29 qualification.

The separate `899ba3119b` reuses one local read-buffer allocation within each
complete native preimage sweep. Every fresh physical read, incarnation check,
policy check, comparison and final current check remains in its original order;
buffer capacity carries no authority across sweeps. Its native SDK build, strict
library and all-target Clippy pass, as do all six real-worker cohort tests. The
unchanged 1,024-entry witness still fails in 56.219 seconds: the original deadline
rejects 30.00259983 seconds against 30 seconds after synchronizing
`objects/index/21/53.idx`, during its final Raw current refresh. Independent
review matches all 3,252 captured inputs to the sealed commit for all five
original invocations. No acknowledgment return, post-stage timings, baseline
output, measured maintenance or independent oracles are reached. Allocation
cost remains unmeasured; this change does not qualify DRV-29 or advance a task.

The separate `6cd9a20105` removes temporary ancestor-path vector construction
from native parent checks. It preserves complete structural validation before
metadata, each exact ordered path, policy and incarnation check, and all original
errors. Its SDK build, strict library and all-target Clippy, and all six worker
tests pass. The unchanged 1,024-entry witness fails in 62.506 seconds. Its actual
Raw acknowledgment returns at Raw-scope elapsed 27.753605488 seconds, then the
original ref deadline rejects 30.177655775 seconds against 30 seconds before
the immutable metadata batch returns. The precise caller check is not localized
beyond that recorded boundary. Independent review matches all 3,252 inputs for
all five original invocations to the sealed commit. Durable selected staging,
post-stage diagnostics, baseline output, measured maintenance and independent
oracles remain unreached. This result establishes no allocation benefit,
throughput gain or DRV-29 qualification.

Shared native test-image registration preserves all 292 specification gates and
69 current T0/T1 gate names. Its compiler output remains explicitly pending on
trunk while the isolated implementation is reviewed. The intended reuse covers
only immutable compilation; each prerequisite and owning fork gate retains its
own exact inventory, execution, protected namespace and fresh fixtures. Source,
feature and profile binding are checked before consumption, and required runtime
references are preserved through AOS fixup. No execution qualification is claimed
from registration or static checks.

The private `7b9c63d9a6` composition now builds that immutable native SDK image
through the actual owning Nix request. Compilation, AOS fixup and discovery pass;
the installed inventory contains 737 tests with none ignored. Independent review
matches all 6,054 tracked pre-invocation inputs and the actual source's 5,000 files
and 875 directories to the sealed commit, and all 3,053 image-bound crate hashes
to that immutable source. Source, feature, test-profile, package working-directory
and runtime bindings survive fixup. All thirteen cold-source prerequisite cases
pass, including the corrected complete older-lineage oracle. The same original
request then fails its mandatory imported-source prerequisite in 75.51 seconds:
the actual local-head/foreign-used-view cold fork returns `Unsupported` at
`gc/runner/tests/source_carry/imported.rs:248`. This result does not establish
deadline expiry. The other two prerequisites and twelve owning cases remain
unqualified in this invocation; only the image and cold-source outputs are valid.
No prerequisite is waived, task accepted or T1 freeze advanced.

The private `1ff700431a` composition keeps imported cold-source qualification
reachable by applying the local Original binder only to locally sourced heads.
The imported path retains its complete historical source, signature, ownership,
physical holder and final current checks. Its native SDK build, strict library
and all-target Clippy pass. The exact mandatory local-head/foreign-used-view
cold-fork case passes in 45.092 seconds with unchanged deadlines. Independent
review matches all 6,061 tracked inputs before and after each of these four
original invocations to the sealed commit. This local regression pass does not
qualify the owning gate, complete native suite or T1.

The separate owning Nix request on that same `1ff700431a` source now completes
with a failed mandatory prerequisite. The shared image compiles, survives AOS
fixup and discovers 750 cases with none ignored. All thirteen cold-source,
the imported-source and all nine source-preservation cases pass. Requalification
passes eleven cases, then its required-index case fails in 7.61 seconds: the
actual result is `Unavailable`, but lacks the expected owning index error and
primary Node identity. The fixture blocks an entire pack after observing the
primary; isolation from source Commit and namespace metadata needs verification.
The relationship-completion error mapper also drops the index wrapper for store
failures. Neither finding permits weakening the owning-index assertion or
changing truthful storage-unavailable reporting. The twelve owning cases remain
unexecuted because their prerequisite fails. Independent review matches all
6,061 clean tracked inputs before and after this invocation, all 5,007 actual
Nix source files and 877 directories, and all 3,060 image-bound crate hashes.
All six derivations bind that same immutable source. Only the image and three
passing prerequisite outputs are valid; no task, milestone or freeze advances.

Mandatory application unit and integration target compilation now passes on
that frozen `1ff700431a` composition. Cargo compiles the targets in 25 minutes
29 seconds; the original hermetic check then completes AOS fixup and registers
its output as valid.
It binds the same independently reviewed immutable source as the owning fork
request; all 6,061 tracked inputs remain clean and byte-identical afterward.
This replaces the missing current compile result without executing those tests
or qualifying subsequent source changes, strict workspace quality or T1.

The separate `a7b4d28a0f` correction isolates the finite required-index Nodes
through actual native puts before source publication, calibrates their real
pack separately from the signed Commit and namespace root, and retains the
owning index error, exact Node and underlying I/O source without changing its
store outcome. The original exact regression passes in 5.949 seconds with
unchanged assertions and deadlines; its SDK library build and strict library
and all-targets Clippy also pass. Independent review matches all 6,061 tracked
inputs to the sealed commit and verifies both source checkouts remain unchanged
through the original executions. The complete owning Nix request and current T1
floor remain required on the combined candidate; no task or freeze advances.

The reviewed Raw durability scope admits only actually created, canonical
immutable metadata outputs unused by any consumed present or absent input.
Complete source/current checks, target descriptor checks and exhaustive final
output validation remain intact. The first `b2d113ee9b` all-target compile stops
at four borrowed temporary view lifetimes in new tests. The separate
`40420fa3ad` correction adds only four retained local bindings, preserving all
production bytes and assertions. Its SDK build, strict library/all-targets
Clippy, four genuine producer tests, ten real durability tests and thirteen
focused cohort/handoff/cancellation regressions pass. The first new-test filter
selected only four cases; the complementary ten run separately against their
exact compiled names, with no ignored selected cases or repeat of the four.
Independent review matches all 3,255 captured inputs to the sealed commit and
verifies they remain unchanged through all eight original invocations.

The unchanged 1,024-entry ordinary witness still fails in 75.880 seconds.
Actual scope eligibility contains 233 outputs; Raw acknowledgement returns at
25.255086930 seconds and durable staging completes at original ref elapsed
28.336830056 seconds. The next genuine candidate-history call takes
22.681971475 seconds, then the original ref deadline explicitly rejects
51.359950697 seconds against 30 seconds with `Expired`. Baseline output,
measured maintenance and independent oracles are not reached. This localizes
the complete history-call span, without measuring its internal contributors or
establishing throughput or DRV-29 conformance. The frozen combined `8e86fc32bc`
candidate passes both mandatory format checks and its complete owning fork
Nix request: all 47 required executions pass with none ignored. These comprise
thirteen cold-source, one imported-source, nine source-preservation, twelve
requalification and twelve owning cases. The image discovers 764 unique tests
with none ignored; all six outputs are valid and bind one independently reviewed
immutable source containing 5,010 files and 877 directories. Independent review
matches all 6,064 captured inputs before and after, all 3,063 image-bound crate
hashes, and the exact builder selectors to the actual execution logs. The earlier
failed requests remain recorded. This qualifies the owning fork request on that
source; the complete current T1 floor remains required before task acceptance.

The separate test-only history diagnostic initially builds its SDK library,
then fresh strict library Clippy finds an unused private cohort wrapper. The
previous cached library checks did not establish fresh production lint
cleanliness. The reviewed two-file `bb1cd0ab7c` correction removes only that
wrapper and updates its two test callers to the tracked installer; publication
bodies and assertions remain unchanged. Private composition `d3409008a9` passes
fresh SDK library compilation and strict library/all-targets Clippy, each
compiling its actual assigned source. The unchanged instrumented witness fails
in 77.395 seconds with `Advance(Expired)` at original elapsed 51.986007554 seconds
against 30 seconds. Complete history takes 24.201056039 seconds; relationship
checking takes 23.354087791 seconds. Its 609 genuine held GETs spend
5.707843655 seconds observing selection, 11.782676067 seconds checking catalogs,
0.649273102 seconds verifying bodies and 5.734147077 seconds revalidating.
These are inclusive child spans, not additional time above the history total.
The root's 568-GET load takes 22.441375823 seconds, while reconstruction and
preparation take only 3.104657 and 11.873441 milliseconds. All 6,064 captured
inputs and the actual executable remain unchanged; baseline output, maintenance
and independent oracles are unreached. This identifies serial read work without
establishing an optimization benefit or qualifying the deadline witness.

The reviewed next candidates retain ordinary per-read validation while bounding
concurrent GETs of already validated frontier references, and separately defer
only unrelated, producer-proven Raw output leaf checks during intermediate sync.
The latter revises the earlier extra implementation promise of every intermediate
physical sample: BKT-13/14, REF-12/15, STORE-30, D-57 and the publication authority
require actual durability, exclusion, current inputs and honest final completion,
not every unrelated output's leaf sampling around every other sync. Actual target
whole-body/descriptor/name/ancestry checks, all consumed present/absent inputs,
source/current predicates, root/control/directory/pair fences, exhaustive final
same-descriptor output checks and real Raw acknowledgment remain required.
Unknown or conflicting roles retain complete checking. Error timing and harmless
read/sync attempts before refusal may change; persistent final faults still refuse.
No specification or freeze changes, task acceptance or performance claim follows.

The reviewed private composition `8d505691b2` implements the bounded frontier
and unrelated-output leaf deferral. Its SDK library build and fresh strict
library Clippy pass; fresh all-target Clippy stops before execution because the
new frontier test constructs the structured `Denied` outcome incorrectly.
The separate test-only `d1a967697b` correction preserves the exact failure kind,
subject, cause and DFS ordering, then all-target Clippy finds twelve configured
test lint errors. Reviewed `f2e623d1ec` and `c1510ba1ed` replace the eleven
`unwrap` calls and one `unwrap_err` with the existing panic-on-failure fixture
helper and explicit outcome matching. Assertions and production bytes remain
unchanged. No runtime test or deadline witness has yet qualified this candidate;
the original failures and cached versus fresh library results remain distinct.

Corrected `c1510ba1ed` passes fresh strict all-target Clippy and all 31 selected
regressions: six frontier, thirteen actual Raw durability, eight loader and four
producer cases. The compiled inventory contains 773 tests. Its unchanged
1,024-entry ordinary witness fails in 66.533 seconds with `Advance(Expired)`;
the original deadline reports 41.813943019 seconds against 30 seconds. Durable
staging takes 27.640839966 seconds and complete history takes 13.816172718
seconds. The 609 genuine held GETs reach eight-way overlap; their cumulative
56.393249669 seconds are overlapping child spans, not wall-clock history time.
All 6,066 captured inputs and the executable remain unchanged. Baseline output,
maintenance and independent oracles are unreached; no broader population is run.

Private test-only `600fd7fd06` adds the integrated GC-29 missing-Trash recovery
witness using the real Pending directory-sync failure, qualified restoration,
fresh mark/backend age, a new incarnation and full new deletion wait before
actual native unlink and Done. Review preserves every existing test body and
changes no production code. Its exact selector joins the existing exclusive
five-minute local-deletion process scheduling class; C/G/D/H, lease and writer
deadlines remain unchanged. Compilation and runtime qualification are pending.

Integrated `971ff5d82c` passes fresh SDK library compilation, strict library
and all-target Clippy, and compiled discovery of its exact new witness.
The first actual execution fails after 110.731 seconds: native deletion and
durable Done complete, but the unchanged helper expects capability generation
6 from an earlier reopen rather than generation 8 captured before deletion.
Later preservation assertions do not execute. All 6,064 captured inputs and
the executable remain unchanged. The earlier read-only target refusal occurred
before compilation and remains separate. Reviewed test-only `b82427b68c` clears
the obsolete reopen override only in the new test, so the unchanged oracle
compares the complete actual pre-deletion record. Its two-file diff and all
6,062 unaffected source images are verified; compilation and execution remain
pending. No complete witness or collector qualification follows.

Corrected `b82427b68c` subsequently passes fresh SDK library compilation,
strict library and all-target Clippy, fresh test compilation and the single
integrated missing-Trash recovery witness in 108.737 seconds: one pass, no
failures or ignored tests. The complete full-D/native-Done and final current
preservation assertions execute. All 6,064 captured source images remain
identical. A wrong-working-directory metadata helper failed before runtime
capture; its refusal is preserved separately, and no pre-runtime executable
seal is claimed. The executable's first-live and post-run captures match.
This actual scoped pass does not qualify the owning Nix collector gate,
post-deletion cold-source witnesses or the complete current trunk floor.

Reviewed private `08d1123ab9` adds three test-only post-Done source witnesses:
ordinary and imported used-view cold reuse, and consumed Original physical
reincarnation refusal after genuine source qualification. Its real deletion
path independently observes full-D elapsed time, durable Done, exact journals
and actual container absence; reopen independently proves the complete
capability-probe successor before preservation comparisons. Compilation and
execution remain pending. Those three exact selectors join the existing
exclusive five-minute deletion process bound, using the measured 100-210-second
deletion cases and 45-second imported cold case as scheduling evidence.
No production clock or collector gate status changes.

Frozen `cd5c6abdaf` subsequently passes fresh SDK build, strict library and
all-target Clippy, compiled inventory and all three exact post-Done witnesses
in 356.588 seconds. The configured profile reports actual execution through
SLOW notices and the complete three-pass summary; individual PASS lines or
per-case timings are not claimed. All 6,070 tracked inputs and the selected
executable remain unchanged through the original invocations. The owning
collector gate, complete deletion matrix and missing-Trash correction on its
combined source remain separate obligations.
The executed fixture's windows are C=30, G=60, D=60 and H=90 seconds;
its retained wait and independent elapsed assertion enforce the full D=60.
An earlier private packet's phrase "full D90" is a narrative error, corrected
separately while retaining the original packet and logs.

A separate `native-local-gc-conformance` auxiliary requires all eleven ordinary
retirement and three post-Done witnesses, plus the six first-ownership,
eleven deletion/recovery, ten preownership restore and one retirement-fault
cases. Its prerequisites retain all five root, fourteen mark, four grace,
nineteen singleton-lease, nine source-carry and one imported-source cases.
That is 94 required executions covering 88 unique selectors; existing overlaps
are retained. The missing-Trash correction on `b82427b68c` must be composed
before qualification. This auxiliary is registered but unqualified.
The current private composition `77d2317e61` preserves the reviewed collector
and missing-Trash correction, with all four shared gate files matching trunk.
Both mandatory formats pass. Its original owning auxiliary request fails in
the required `gc-mark-reachability` dependency: the first seven mark cases
execute and pass, then the checkpoint/reopen case receives `Denied` for commit
to `refs/heads/_/main` at its signed index-publication setup. The failing case
takes 2.24 seconds; this is not evidence of deadline expiry. Printed compiled
inventory contains 768 cases. The fourteen direct auxiliary cases never execute,
and the other interrupted prerequisites and unfinished SDK image supply no
completed conformance outputs. All 6,074 captured source inputs remain unchanged;
the original failure and actual per-case reports are retained without retry.
The denied setup requires diagnosis before replacement qualification.
Source diagnosis identifies revision-3 index publication on a fixture that
selected Legacy authoring before installing its protected Guard. A late
profile replacement would violate the existing Guard snapshot and is rejected.
Reviewed private `767f5dd234` instead opts only two indexed tests into explicit
current/property revision 3 and attribute revision 2 before the first Guard,
native initialization and genuinely signed source. Both reopen paths retain
that independently selected profile; the changed-ACL refusal changes only its
original ACL. Legacy fixtures and every existing oracle remain unchanged.
Both formats, SDK build and library Clippy pass, but all-target Clippy finds
a missing optional field in the existing Legacy restore-copy initializer.
That compiler failure is preserved; no inventory or runtime starts on it.
Reviewed private `05e50903cb` adds only `authoring: None` to that initializer.
All 6,074 tracked inputs, modes and symlink targets are independently verified;
both formats and fresh SDK/library/all-target Clippy pass. Compiled discovery,
the two actual indexed cases and owning collector qualification remain pending.
Discovery on that unchanged corrected source subsequently succeeds with 768
library cases and both exact indexed selectors present once and nonignored.
The first checkpoint/reopen case executes once and fails at writer begin with
typed `Unsupported` after 2.112 seconds, before its checkpoint assertions.
The exact indexed-role case and owning checks do not execute. All original
invocations are terminal and the complete source and selected executable
remain unchanged; the failure is preserved for diagnosis without retry.
Reviewed private `9fa5a657fc` corrects only three test files: an indexed reopen
captures each actual signed head and parent with its independently selected
view context and attribute revision from the still-live owning Guard. A fresh
Guard installs those ordinary `ViewSelection` inputs before native initialization;
its native factory still revalidates actual protected Guard and Original state.
The checkpoint path includes its newly published signed head, while Legacy
fixtures retain their original path. The handoff conveys configuration, not
completed history or publication authority. Every existing oracle, root, clock,
window and trap remains unchanged. Independent review verifies the complete
three-file diff, 6,074 tracked hashes, modes and symlink targets; both formats
pass. Owning collector and auxiliary qualification remain pending.
The same frozen source subsequently passes fresh SDK compilation, strict library
and all-target Clippy, and discovery of 768 native cases. Both previously
failing exact indexed cases execute once and pass under unchanged serial/default
settings. The owning `gc-mark-reachability` Nix gate then passes all fourteen
registered exact cases with zero failed or ignored. Independent review matches
the actual successful names, log hash, result and derivation input/output bindings,
and all 5,020 immutable source files with their executable bits against the
frozen worktree. The broader local collector auxiliary is still running;
its partial prerequisite results do not qualify its complete fourteen-case body.
That original auxiliary request subsequently exits successfully on the same
frozen source. Its ten prerequisites report eighty successful exact executions,
and all fourteen direct local-v1 retirement and post-Done cases pass, totaling
94 successful occurrences across 88 distinct cases with zero failed or ignored.
The earlier owning mark output is reused as its same-source prerequisite;
it is not executed a second time. Independent review verifies all fifty
evidence artifacts, the direct discovery and execution selectors against their
actual successful names, all twelve derivation outputs and their common source,
and all 6,074 tracked contents, modes and symlink targets. The two indexed
Nextest cases retain unchanged pre/post executable bindings. The packaged
SDK test image also matches all 3,069 recorded source inputs and its eight
finalized files. These successful checks cover ordinary local-v1 retirement,
physical recovery and post-Done reuse on this source; they do not qualify
the separate joint candidate or the missing D-82 collector paths.
GC-15, GC-16 and GC-29 also require D-82 copied-retirement and permanent-owner
recovery. The current source implements their codecs and portable-copy
registration, but no genuine copied or permanent-owner collector path.
Local-v1 success or Unsupported-only refusal cannot qualify those requirements.
The full `gc-two-phase-delete` gate therefore remains explicitly pending;
this local auxiliary cannot close T-GC-1 or permit the T1 exit.

Reviewed private `f1f178a8cb` adds opt-in, test-only aggregate timings for Raw
installation, recapture and synchronization. Independent comparison preserves
the ordered production tokens of all four instrumented files, and both complete
format checks pass. Timing groups are inclusive and must not be added together;
byte counts describe expected bodies, not measured successful reads.
Initial compilation and runtime qualification were pending on this source.
Separately, review identifies missing witnesses
for ordinary and imported cold-source preservation after physical Done;
retirement-only source checks do not prove that outcome.

Frozen `f1f178a8cb` subsequently passes fresh SDK library compilation, strict
library and all-target Clippy, compiled inventory and all 31 exact regressions
in 1.205 seconds. Its single unchanged 1,024-entry ordinary witness fails in
62.885 seconds with a store denial. The trace identifies the actual retained
deadline refusal at 30.024610374 seconds against 30 seconds, before final Raw
synchronization. The thirty bounded install batches prepare and recapture 233
outputs; tracked installation takes 26.665524070 seconds, including
26.432649637 seconds in native execution and receipt waits, 0.166761583 seconds
in preparation and 0.064502962 seconds in recapture. These nested intervals
must not be added to the installation total. Internal validation, syscall and
dispatch contributors remain unsplit. Final synchronization of those 233
outputs, Raw acknowledgment, durable staging, history, baseline output and
maintenance oracles are unreached. Earlier setup synchronization aggregates
measure different publications and cannot substitute for the missing final
measurement. All 6,067 captured inputs and the actual executable remain
unchanged through the original executions. No retry, speedup or full-gate
qualification follows.

Frozen `6982ff4694` subsequently passes fresh SDK compilation, strict library
and all-target Clippy, compiled inventory and all 37 exact regressions in
1.379 seconds. Its one unchanged 1,024-entry ordinary case fails after
65.740 seconds with explicit expiry at 39.234267728 seconds against 30 seconds.
Within that execution, thirty native cohorts install 233 outputs. Tracked
installation takes 14.878164579 seconds, including 14.661457031 seconds in
execution and receipt waits. Inclusive write, file-sync and no-replace-rename
groups take 3.419065483, 4.367444422 and 6.419222802 seconds respectively;
their validation and syscall substeps remain unsplit. Final Raw acknowledgment
returns after actual synchronization of 241 output records. Its nested fresh
preimage work takes 7.303011136 seconds across 986 sweeps and 522,444 attempts;
330,665,896 bytes describe expected lengths, not measured reads. Durable staging
is observed at 27.129154822 seconds of the original deadline, then history takes
11.849036594 seconds. Baseline, maintenance and independent oracles remain
unreached. All 6,068 captured inputs and the selected executable remain unchanged
through the original invocations. Inclusive groups must not be added to their
parents; differing reach between executions establishes no speedup or cause.

Reviewed private `dad6f7714f` implements the scoped installation refinement and
seventeen additional real producer, worker and publication-boundary witnesses.
Every consumed present or absent input, current staging and target body,
physical binding, exclusion and deadline retains its checks. The complete
cohort boundaries, actual creation receipts, recapture and full verification
before selecting the publication slot remain required. The earlier `1f13cafc81`
qualification stops at two test-only borrow-checker errors; `dad6f7714f` corrects
only the fixture observation's drop order after all assertions. Those original
diagnostics remain preserved. Fresh strict all-target Clippy and compiled
discovery pass; the actual inventory contains 790 cases. All 54 exact selected
regressions execute once and pass in 2.532 seconds, including the seventeen new
fault cases. Independent review matches their literal passing results to the
compiled inventory and verifies all 6,075 unchanged source inputs and the
captured executable before and after each original invocation.

Its single unchanged 1,024-entry ordinary witness still fails: the original
ref deadline explicitly rejects 40.799392140 seconds against 30 seconds.
The case fails after 67.078 seconds. In that same execution thirty cohorts
prepare, install and recapture 234 outputs; the earlier execution's 233-output
count is not substituted. Tracked installation takes 15.696339526 seconds,
including 15.398183130 seconds in execution and receipt waits. The final Raw
acknowledgment interval takes 8.340082659 seconds, with nested fresh preimage
work taking 6.903716614 seconds across 990 refreshes and 524,242 attempts.
The 332,975,554 expected bytes do not measure actual body reads. Durable staging
is observed at 28.715111480 seconds of the original deadline; history then takes
11.747015140 seconds. Baseline publication, measured maintenance and independent
oracles remain unqualified, and the other five required populations remain
unrun. Nested timing groups are not additive, and these separate executions
establish no speedup attribution or successful DRV-29 qualification.

The next reviewed Raw-only refinement may omit the outer pre-sync refresh
duplicated by the complete inner refresh after preparing the current retained
descriptor. Preparation performs only a bounded same-descriptor body read;
no durability or publication effect occurs before the retained inner check.
That check must still validate every consumed present and absent input, source
and control body, current target body and physical binding, directory, name,
pair, exclusion and current deadline immediately before the actual sync.
Inner post-sync checks, caller post-body checks, outer post-refresh, directory
durability, exhaustive final descriptor and projection checks, Raw associations
and private acknowledgment remain required. Ordinary callers keep their existing
schedule. The original clock, start and maximum remain fixed, but removing an
earlier duplicate sample changes refusal precedence and may miss a transient
source or clock fault restored before the retained checks. This is not a claim
of identical sampling or observations. Qualification requires a real handoff
after preparation and before the inner refresh, actual syscall-entry evidence,
post-body current refusal and cancellation/exclusion witnesses. The existing
post-sync completion event alone cannot prove that no syscall was attempted.
Implementation, those witnesses and the unchanged six-population conformance
gate remain pending.

Reviewed private `6cc17e62af` implements only that Raw-specific outer-refresh
guard, retaining the ordinary schedule and every inner, post-body, directory
and final check. Four new tests cover six prepared dependency and target faults,
deadline refusal before actual syscall entry, current refusal after the actual
post-body read, and exclusion retention after dropping a native receipt waiter.
The latter uses an actual worker thread and private channel; it does not claim
Tokio-future cancellation. The thirteen existing scoped tests remain a
byte-identical prefix. Both mandatory formats pass; compilation, the actual
selected runtime corpus and the unchanged large-population gate remain pending.

That frozen candidate now passes fresh SDK compilation, strict library and
all-target Clippy. Compiled discovery contains 794 native library cases; the
exact previous 54 regressions and four new witnesses each execute once and
pass, with zero ignored cases, in 2.569 seconds. Independent review verifies
all six original invocations, the actual passing-name counter, all twelve
before/after source snapshots, 6,076 unchanged tracked contents and modes,
and the selected executable captured before and after runtime. The source
wrapper follows symlink contents and modes; clean Git separately preserves
the tracked link targets. These focused results do not qualify publication.

The single unchanged ordinary 1,024-entry witness fails after 71.643 seconds.
Its original deadline explicitly rejects 43.783866096 seconds against the
unchanged 30-second maximum. That execution installs 233 fresh outputs in
thirty cohorts; the preceding candidate's 234-output count remains separate.
Tracked installation takes 16.887083587 seconds and the final Raw
acknowledgment interval takes 6.993096876 seconds. Durable staging is observed
at 27.524723947 seconds of the original deadline. The subsequent history
entry-to-return interval takes 15.820675950 seconds; the enclosing post-stage
interval takes 16.103341643 seconds. Nested measurements are not additive,
and separate executions establish no causal speedup. Baseline publication,
maintenance and independent oracles are not reached; the other five required
populations remain unrun. The original process is terminal, with no retry or
source change. DRV-29 and the complete T1 exit remain unqualified.

Independent pairing of the original history interval's 609 complete held-GET
scopes separates observation, catalog checking, member-body verification and
final backend revalidation. Their interval unions are respectively
3.972804657, 7.481632365, 0.774585248 and 4.821814172 seconds. Concurrent
phase unions overlap: they are not additive exclusive time, physical I/O,
CPU measurements or complete Guard authorization. Fresh selected state,
actual shard/filter and container bytes, membership, current physical checks,
Guard policy and post-await Original revalidation remain required. A reviewed
two-file test-only loader profiler at private `a89a88aa90` separates awaited
reads from local hash, decode, context/traversal and owner-binding work without
changing ordered production operations. All 2,365 stripped production tokens
match `6cc17e62af`; 6,077 tracked contents and modes are independently sealed,
and both formats pass. Its diagnostic child field holds no authority and
does not alter the Fetcher's existing field moves. Compilation and runtime
qualification remain pending; no read reuse or optimization is qualified.

That sealed `a89a88aa90` subsequently passes fresh SDK compilation, strict
library and all-target Clippy, and compiled discovery of 794 native library
cases. The same 58 exact regressions each execute once and pass in 2.373 seconds.
The single unchanged ordinary 1,024-entry witness fails after 72.632 seconds,
with explicit expiry at 41.783607463 seconds against the original 30-second
writer maximum. Baseline publication, maintenance and independent oracles
remain unreached; the other five required populations remain unrun.
Independent review verifies all six original terminal invocations, all twelve
source snapshots, 6,077 unchanged tracked contents and modes, and the actual
selected executable captured before and after runtime. Previous passing-name
selectors are unchanged; this result does not qualify DRV-29 or the owning gate.

The same execution's dominant history load takes 10.587344641 seconds with
568 planned GETs, 577 identity checks and 578 decodes. Its aggregate measured
namespace and auxiliary read-await intervals total 10.560442253 seconds;
measured local hashing, decoding, context/traversal and owner binding total
0.002768151 seconds. Independent review pairs all three emitted aggregates
with their immediately following completed-load boundaries and actual work
counters. Read-await includes Store work, byte clones and scheduling, while
the local groups omit unmeasured costs. These are neither physical disk wait
nor complete CPU measurements, and separate executions prove no causal speedup.

Source review finds the otherwise transparent native backfill fixture omits
its existing `LocalFs::read_protected_record` delegation. Reviewed private
`201f568606` adds exactly seven lines forwarding that existing method to
`TokioLocalFs`; no trait, production consumer or payload API changes. Removing
only the method restores the fixture byte-for-byte, including the publication
ACK fault, typed-content counters, setup and assertions. All other crate bytes
match the profiler candidate. Both mandatory formats pass and all 6,077 tracked
contents and modes are independently sealed. The supported native read still
propagates errors without scalar retry and retains the existing selected
resolver's final physical fence. Its dispatch and observation timing can differ;
no identical sampling or performance improvement is claimed. Fresh compiler,
protected-read, ACK/counter and deadline qualification remain pending.

That frozen `201f568606` subsequently passes fresh SDK compilation, strict
library and all-target Clippy, and actual discovery of 794 native cases.
All 76 reviewed, disjoint exact regressions execute once and pass in
173.597 seconds, including protected/scalar reads, final physical fences,
native backfill and actual ACK/counter checks. One successful case is reported
as slow; no selected case is ignored. Its single unchanged ordinary 1,024-entry
witness then fails after 65.432 seconds with explicit expiry at
38.539708890 seconds against the original 30-second writer maximum.
Baseline publication, maintenance and independent oracles remain unreached;
the other five required populations remain unrun. Independent review verifies
all six original terminal commands, twelve source snapshots, 6,077 unchanged
tracked contents and modes, actual compiled selections and the selected
runtime executable's pre/post bindings. The failure is preserved without retry;
these passes do not qualify DRV-29 or prove a cross-run speedup.

Reviewed private `85558972ae` adds six public format properties for the existing
common Memo, closed index bindings and recipes, opaque index keys, and generic
empty Nodes in explicit index roles. SDK compilation, strict library and
all-target Clippy pass. The entire public integration corpus executes all 53
cases without failures, ignored cases or filtering; the five required private
preimage properties each execute and pass. A cached no-default-features build
also passes. All 6,066 tracked inputs remain unchanged. An earlier read-only
shared-target refusal occurred before compilation and remains separately
recorded. These Cargo results do not qualify the owning Nix gates, published
common-Memo decoder witnesses, WASM execution or the complete trunk floor.

The shared `core-fuzz` harness now requires the exact reviewed 53-case compiled
inventory and every corresponding successful execution, rejecting omissions,
duplicates, ignored cases and filtering rather than accepting a nonempty count.
Its source-bound Nix qualification remains pending. D-112 adds three positive
common-Memo field models and 249 independently produced rejecting wires,
including every strict prefix of the positive records. Existing foundation
payload and descriptor bytes remain unchanged. The twentieth mandatory golden
consumer must compare independent bytes and identities, decode exact Memo fields
and reject every negative through the owning codec. Reviewed private
`db62c57e22` supplies the independent Python producer and public Rust consumer.
Fresh SDK compilation, strict library and all-target Clippy, compiled discovery
and the three exact serial Memo cases pass. The cases compare all positive
fields, bytes and identities, reproduce and reject every negative, and decode
the unchanged foundation payload through the common Memo codec. The final
runtime summary reports three passed and zero skipped in 0.248 seconds; the
configured profile hides individual passing status lines. Independent review
matches all artifact hashes, the exact nonignored inventory and filter, all
6,071 unchanged tracked inputs, and the captured prerun executable binding.
The twentieth source-bound Nix consumer and complete golden gate remain pending;
these scoped Cargo results do not qualify the full format or trunk gate set.

The decoder audit maps the actual 53 properties to 76 covered API groups,
including the six new cases and the older configured-registry property omitted
from the prior 46-case metadata. It separately identifies implemented GapBinding,
ConsumedViewInterpretation and LocalGcReconciliation codecs without public
property coverage. The shared catalog prospectively requires five additional
cases for those formats and two concrete nested allocation-order defects.
Graft recipe decoding copies embedded Entry bytes before the Entry size bound;
commit decoding copies embedded provenance token bytes before the token's block
and grant bounds. Those nested limits must be checked against borrowed data
before ownership. The corrective task and exact 58-case source-bound gate remain
pending; malformed-input refusal alone does not establish allocation ordering.
Reviewed private `148be2c4ed` implements both borrowed-before-copy corrections
and exactly five additional public properties. Existing property bodies remain
byte-identical prefixes, and both mandatory format checks pass. The shared
mapping now describes 79 codec groups and all 58 declared cases, preserving the
previous groups and separately identifying unimplemented formats. Compilation,
actual inventory, execution and source-bound Nix qualification remain pending;
source declarations and rejecting token inputs alone do not observe allocation.
The composition `05f4a41a5e` passes SDK compilation and strict Core library
Clippy, then stops at strict all-target Clippy with nine diagnostics from one
missing explicit import in the new reconciliation property. That type resides
in the public `publication::reconciliation` module, not the parent wildcard
import. All 6,072 source inputs remain unchanged through the original calls;
compiled discovery and runtime stages are unexecuted. The shared API mapping
uses the correct nested path; a test-only import correction must pass fresh
qualification before the 58-case corpus is claimed.
Reviewed test-only `c7692f308e` adds exactly the missing nested import and passes
both mandatory format checks. Existing test bodies and production bytes remain
unchanged; compiler and runtime replacement qualification remain pending.

The corrected private composition `bf1fc85e74` subsequently passes both
mandatory format checks, strict Core all-target Clippy, compiled discovery and
the complete 58-case public corpus. Every selected case executes once and
passes in 5.149 seconds, with zero aggregate skips. The complete Core suite
also executes all 718 cases across eight binaries, passing in 17.970 seconds
with zero aggregate skips. This includes all three Memo consumers and the five
required private preimage properties. The no-default-features Core library
build passes. Independent review verifies all 42 packet artifacts, every
original terminal result, all 6,072 unchanged source inputs and all eight
runtime executables' before, after and final captured hashes and metadata.
The preserved original compiler failure and corrected read-only log parser
error do not cause a runtime retry. These results do not execute doctests,
observe allocations, qualify WASM or establish the complete trunk floor.
The owning source-bound `core-fuzz` Nix gate also passes all 58 public cases
and each of the five exact private cases. Independent review matches all 5,018
immutable source files to the frozen tracked bytes, symlinks and executable bits,
including all 61 Terrane RFC files, and verifies the derivation's source binding
and actual successful executions. Earlier SDK results retain their original
source scope. The original complete twenty-consumer golden request fails at
the owning index-reference consumer: three stale test-template calls omit the
explicit current revision required by `RecordedContext::new`. All 6,072 source
inputs remain unchanged. The original compiler diagnostics are preserved;
the complete golden gate and its replacement qualification remain pending.

Reviewed private `4a1551897c` supplies the explicit independently selected current
revision 3 in exactly those three template calls. Recorded revisions 1 and 2
retain their inert later metadata; the revision-3 namespace placement refusal
and every existing assertion, model and wire remain unchanged. Both mandatory
formats pass. The owning index suite executes all seven exact groups and passes
its independent 176-wire checks and strict generated-test Clippy. Its subsequent
complete golden request passes all twenty owning suites and 104 exact successful
test invocations, including all three Memo cases and their strict Clippy check.
Each exact invocation reports one passed, zero failed and zero ignored; sibling
filtering is intentional and does not omit a registered owning selector.
Independent review verifies all 58 packet artifacts, each consumer's actual
evaluated selectors against its successful log, every result and reference
output, and all 6,072 unchanged source inputs. All twenty consumers bind to the
same reviewed immutable source, whose 5,018 files include the complete 61-file
Terrane RFC. The aggregate inventory covers 31 reviewed sections. Earlier
partial or failed golden requests remain separate historical evidence; this
success does not qualify the complete current trunk floor or advance a task.

Prepared private `da49d4ae08` composes the reviewed native `201f568606` with
current trunk progress and exactly 26 independently reviewed source paths:
ten Core/property/Memo inputs from `bf1fc85e74`, two golden-template corrections
from `4a1551897c`, and fourteen test-only collector paths from `9fa5a657fc`.
Every carried file matches its recorded source byte-for-byte; collector
production, normative specifications, dependencies and package definitions are
unchanged. All 6,087 tracked contents, modes and symlink targets are sealed,
and the mandatory formatter pair passes. Compiler, runtime and full-floor
qualification remain unrun; historical component successes do not qualify this
joint source. The original collector run and queued native-read qualification
retain their separate frozen sources and evidence.

Read-only review of that joint source identifies a remaining TEST-4 coverage
gap: existing algebra tests lack an independent ordered-map model for every
current trunk operation, and equal-root or loose work bounds do not prove
internal triple-equal subtree pruning. An isolated test-only correction adds
separate map semantics and an exact changed-ancestor expansion witness through
seven existing registered selectors, preserving their original assertions.
Its initial strict Clippy run finds a range-loop lint; the mechanical correction
on private `e63ae23652` passes fresh Core compilation, strict all-target Clippy,
the no-default-features build and both mandatory formats. Its seven exact
registered cases then pass in 0.780 seconds, and the complete Core run passes
all 718 tests with zero skips in 18.140 seconds; strict private rustdoc passes.
Independent review binds actual compiled nonignored cases, original commands,
unchanged 6,092 inputs and all ten pre/post executable captures. The original
reporting omits individual successful names, so full-run coverage depends on
the unfiltered command, compiled inventory and zero-skipped summary.
The subsequent test-only cleanup on `f5f1f3a57d` documents reachable panics and
removes one newly duplicated assertion; both mandatory formats pass. Its owning
graft, diff and merge Nix checks pass 25, five and 38 exact cases respectively,
including the merge gate's native SDK cases. All 68 executions pass without
failed or ignored cases. Independent review checks the actual ordered gate
selectors and successful names, all 5,922 immutable source entries, 5,038
included tracked-file bindings, and the seven new helpers' registered callers.
These owning checks do not qualify the full trunk floor. This work changes no
production behavior or format.
The `perf-merge-delta` reporting gate
remains T6 work under T-PERF-1, independently of these current T1 test obligations.

The next ordinary-read refinement is committed locally before T1's freeze:
it combines the three ordinary leaf dispatches after unchanged ordered parent
validation, retaining nofollow whole-body reads, named incarnation checks and
existing absence/error mapping. Native SDK, standard/send, standard/WASM and
no-default builds pass; the new portable import and unreachable-expression
warnings found during qualification are corrected without lint exceptions.
Both mandatory formats pass. Strict native all-target Clippy still rejects
the trunk's existing unused code and test lints; no clean trunk result is
claimed. Fourteen exact recipe and consumer witnesses are registered in the
owning runtime and bucket-layout gates. Their private implementation on
`03945b9b67` passes native SDK compilation and strict native library and
all-target Clippy. Its four owning portable compile configurations pass;
the separately requested strict no-default Clippy run fails nineteen existing
unused-import and dead-code diagnostics, without ordinary-read diagnostics.
The fresh native inventory contains 812 cases and binds all ninety selected
regressions exactly once, nonignored, to the actual current executable and
suite directory. The original serial run completes in 175.721 seconds with
88 passes and two failures: initialization already creates the generation-one
manifest and its index directory, contrary to two new fixture assumptions.
All 76 prior regressions and twelve other new witnesses pass, with all 6,098
source contents and modes unchanged across the run. The conditional indexing
deadline witness and downstream gates do not run. Reviewed fixture-only
`f2dd429256` selects absent generation two and explicitly replaces the existing
index directory before testing an unsafe parent; assertions, counters,
production behavior and deadlines remain unchanged. Its strict native
all-target Clippy and fresh 812-case inventory pass. The original corrected
serial regression run passes all ninety selected cases in 160.647 seconds,
with one successful slow case and 722 unselected cases. Independent review
binds every successful literal to the actual executable and unchanged 6,098
source contents and modes. The exactly-once unchanged ordinary 1,024-entry
indexing witness then fails: its writer expires at 39.200033752 seconds against
the original thirty-second maximum; the complete test fails in 65.116 seconds.
The other five required populations remain unrun. The separate owning-gate
continuation completes on unchanged `f2dd429256`: `runtime-agnostic` passes all
thirteen cases, including six new recipe witnesses; `bucket-file-layout` passes
all nineteen cases, including eight new consumer witnesses. Independent review
binds both outputs to the actual workspace source and all 5,044 included tracked
files, preserving the 1,054 excluded tracked paths and unchanged 6,098-file
checkout. The required `rust.aos-test-targets` build compiles the configured
twenty-nine Linux packages' unit and integration targets on that same source;
it executes no tests and retains the existing compiler warnings. Both mandatory
Rust and Nix format checks pass. These successes establish read semantics and
compilation scope without retrying or qualifying the failed deadline witness.
The reviewed seven-file private feature-boundary correction on `a91cf86221`
fails its first strict no-default library check with two remaining unused
imports: the provenance module qualifier and `SelectedReadInterpretation`
reexport. Its later profiles and principal runtime tests remain unrun; a minimal
correction on `b98ace483a` passes strict no-default library and all-target
Clippy. Both genuine principal tests and the portable graft-interpretation
test are discovered before exact execution and each passes without ignored
cases on the same compiled executable. The following strict `std` all-target
check stops on three unused test helpers/imports; later profiles and private
rustdoc remain unrun on that source. The reviewed correction `a5efcc7ceb`
adjusts only their existing consumer feature boundaries. Rebasing it onto the
shared gate correction preserves every owned Rust file and produces
`ebf6894409`. Strict no-default library and all-target Clippy pass. The test
launcher then omits required Cargo arguments and fails before running tests;
the original failure is retained and the two passing checks are not repeated.
The corrected continuation passes both genuine principal tests and the portable
graft-interpretation test, each discovered and executed exactly with one pass
and no ignored cases. Strict all-target Clippy passes for `std`, `std,send`,
`std,wasm` on the native target, and `tokio,surface-sdk`; strict native private
rustdoc also passes. Independent review verifies every command, log hash,
preserved test executable and unchanged 6,098-entry source manifest. These are
direct checks; the owning feature-matrix and combined-source checks remain
required. Original failures and source seals are retained without lint
exceptions. A CRATE-29 source audit
also finds `surface-sdk` absent from both compatible feature-matrix aggregates.
The shared gate now selects it in the native and native-target WASM-binding
profiles and rejects declared-feature inventory drift; its full execution on
composed source remains required. Test-only native-check instrumentation
on `772cf43ea7` passes source review: removing the reviewed diagnostic insertions
restores both production files' exact original bytes. Its rebase `acbc592b0b`
preserves all six owned files and changes only the shared gate and progress
record. The private merge `f9c938d25a` combines it with qualified `ebf6894409`:
all twelve portable file images match that source, all six diagnostic images
remain unchanged, and the worktree is clean. All six combined direct Clippy and
private-rustdoc profile checks pass, followed by the native build and test
compilation. The first Nextest inventory command rejects Cargo's `-j` argument
before discovery; its original failure is preserved and the continuation uses
the installed tool's `--build-jobs` option without repeating the passing stages.
Fresh inventory binds all one hundred selected cases, nonignored, within 822
native cases to the actual compiled executable. The ten new diagnostic cases
and ninety existing regressions pass with tracing off and again with tracing on.
Independent review verifies 190 individual PASS rows; the first ten-case run
instead has an exact selector, prior fresh inventory and ten-of-ten successful
summary. Its binary-verification helper completes after the run, a preserved
ordering limitation rather than a claim of completed preflight. Later batches
await successful preflight completion and record individual results. The owning
`native-profile-quality` Nix gate passes on the same source, independently bound
to all 5,046 included tracked files with 1,054 exclusions retained. The owning
`native-checked-mutation-publication` and `native-written-mutation-sync` gates
also pass their respective six exact cases on that source. The written-sync
gate prints each case twice, which represents six executions rather than twelve.
The required application-target gate compiles the configured 29 packages' unit
and integration targets without running them; both exact format commands pass.
All nineteen reviewed qualification stages are terminal and green, with the
original failed inventory invocation retained. Independent review confirms the
actual commands, environments, log hashes and unchanged 6,100-file source images
and modes. One instrumented 1,024-record deadline diagnosis is authorized only
after fresh exact discovery and completed source/executable preflight; no other
population or unchanged retry is authorized. Read-only audits also verify that
all 304 Core file images match
the qualified algebra snapshot and the existing GC fixture corrections are
already present; no further source transplant is needed. These local commits
remain unpushed; no deadline improvement or task acceptance is claimed.

That single instrumented diagnosis fails with writer `Expired` at
39.181033078 seconds against thirty seconds; the original test takes 68.693
seconds within the unchanged 120-second process bound. Fresh discovery and
source/executable preflight complete before launch, and all 6,100 source images
and the compiled executable remain unchanged afterward. The complete first
transcript contains 67 cohort, twenty Raw durability and 613 held-content scopes,
with no missing or duplicate boundaries; repeated final failure output is
excluded from analysis and retained in the original log. Fresh parent checks and
opens dominate the observed native validation interiors, while the enclosing
rename spans mostly measure retained checks. These overlapping measurements do
not establish a speedup. Capacity-only reuse of parent-path scratch is committed
on `0ba9444ee9`, preserving every fresh observation and the original refusal
order. All nineteen supporting qualification commands finish with exit zero:
the ten new and one hundred existing native cases pass individually in each
trace mode; strict Clippy and private rustdoc pass for all three profiles; the
owning profile-quality and two six-case mutation checks pass; the required
29-package application-target compilation and both format commands pass.
The first ten-case observation helper rejects padded Nextest ordinals despite
actual runtime success. Its original verifier failure is preserved, and
independent read-only extraction verifies all ten named passes without rerunning
the test. All 6,102 tracked source contents, modes and symlinks remain unchanged.

The subsequent single ordinary 1,024-record case fails during baseline
publication with `Denied { verb: "commit", pattern: "refs/heads/_/main" }`,
taking 76.727 seconds within the unchanged 120-second process bound. Its
thirty-second writer setting remains unchanged. The trace-off log contains no
explicit expiry detail; the denied-error contract strips diagnostic sources,
so neither expiry nor a capacity regression is established by this result.
Fresh exact discovery and successful source/executable preflight precede the
run; the source and executable remain unchanged afterward. The original
transcript and an independently hashed copy of the tested executable are
retained. No retry or other indexing population runs. The reviewed class
dictionary witness on `7c71e91bc5` has begun its separate owning qualification.
That build initially waits for the shared Cargo target lock. Other Cargo jobs
are observed, but its exact lock owner is not bound; machine-wide exclusive
execution is not assumed. A proposed direct syscall substitution is deferred
because the pinned standard library's flags, retries and stat fallback behavior
are not equivalent to that proposal.

The class candidate's focused native witness, whole `derived-attr-record`
gate and all five CDC gates now pass on `7c71e91bc5`. Its application-target
compilation and exact formatter pair also pass, completing all thirteen
qualification stages. The six owning gates report 77 named test executions with
no failures or ignored cases; the separate focused witness passes once. The
29-package application check compiles unit and integration targets without
running them. The frozen source and selected executable remain unchanged.
These results do not establish the complete current floor. A receiving-contract
review also confirms that the broader store gates select real final-to-nonfinal dedup and
inventory-only manifest refusals; their current-source executions remain
required. Existing held-upload effect-counter cases are outside those gate
selectors and have no inferred runtime result.

A separate read-only publication review finds that every bounded cohort
deep-copies the same immutable candidate-body map. Private `79719bc59b` replaces
those copies with shared immutable ownership, retaining per-cohort promotion,
active names and conflict classification. It changes only the private scope
implementation and preserves every fresh observation and current check. Its
source diff is reviewed. Its source and metadata preflight passes; the first
compiler invocation stops before compilation because the sandbox makes the
prescribed shared target read-only. That result is retained while the same
command resumes with the required filesystem access. No candidate test result
is established by the preflight or stopped command.
The resumed compilation and both strict Clippy profiles pass. Actual compiler
output binds a newly compiled native executable to the frozen candidate, and
fresh discovery lists 832 cases. The first selection proof stops because three
producer names have incorrect module prefixes. One scope case is mistakenly
launched before that failure is inspected; it passes, but does not repair the
failed selection proof. The original failure and execution are retained. An
additive correction changes only those three selectors to their discovered
names; independent review verifies all 28 exact nonignored matches and the
current executable hash. All 22 exact behavior cases then pass once, with
distinct run IDs and one-case passing summaries; the first case is not repeated.
The whole native-profile quality check passes, but atomic-write stops at
`partial_generation_is_unpublished_and_retry_uses_a_fresh_generation`: the
unacknowledged write succeeds instead of returning the intended injected error.
The original gate exits one, with builder exit 101 and one failed case; all six
population cases and the remaining qualification stages stay unrun.
Read-only diagnosis proves the wrapper only injects MANIFEST faults for a
standalone rename probe. Actual immutable cohort dispatch reports `Other`, so
this execution never injects the intended MANIFEST error. This is not evidence
that production acknowledges a genuinely injected rename failure.
The parent registers two exact targeted-rename witnesses in the atomic-write
gate and creates an isolated corrective worktree. Its test-only destination
fault must execute at the existing pre-syscall boundary, preserve earlier cohort
installs and refuse native acknowledgment; a nonmatching destination must still
complete. Existing generation visibility, independent reopen and fresh-retry
assertions remain required. The frozen correction passes the SDK build,
strict native all-target Clippy, native test compilation and fresh discovery;
Tokio-only all-target Clippy exits zero with its retained baseline warnings.
The actual non-fresh compiler artifact and 834-case inventory bind the current
source, and all eleven requested cases are exact nonignored matches. The five
focused cases pass once, including both destination-specific witnesses and
the existing partial-generation visibility, reopen and fresh-retry case.
The first ordinary 1024-record population then fails in baseline publication
with a denied commit after 65.627 seconds. Diagnostics are unset, so this
execution does not establish an explicit expiry or a cause for that denial.
Tracked source bytes and modes and the native executable remain unchanged
through the original executions. The first-failure sequence leaves the five
larger or adversarial populations and its remaining qualification stages
unrun. Independent bucket qualification starts in a separate finite sequence
with the atomic-write and generation-manifest gates, application compile-only
check and required formatting pair; it does not retry the failed population.
The whole atomic-write gate passes ten exact cases, including the targeted
witnesses and original partial-generation test, then fails the native creation
case's exact effect trace. The original gate exits one with builder exit 101;
generation, application compilation and formatting stay unrun in that sequence.
Independent comparison finds exactly one extra actual root-directory operation
between transaction rename and selecting commit-slot staging write. Source
review identifies the real complete staged-payload verification barrier;
the test's expected trace omits it. The proposed test-only correction requires
that exact operation and ordering while preserving every equality, nonce,
association, body, projection and acknowledgment assertion. Original failures
remain retained; changed-source qualification is still required.
The test-only correction on `4607ffa0fb` passes SDK build, strict native
all-target Clippy, Tokio-only all-target Clippy with its retained baseline
warnings, native test compilation and fresh discovery. Its actual non-fresh
compiler artifact binds 834 discovered cases to the corrected source. The
focused creation case passes once, and the whole atomic-write gate passes all
eighteen exact cases, including the previously failing creation trace. This
qualifies that frozen gate version; the subsequently expanded registry also
requires ten Raw durability classification witnesses and remains unqualified.
The generation-manifest gate then passes four index-policy cases but exits one
because `physical_exclusion_overrides_live_rows_during_fresh_admission` is absent
from its actual test inventory. The missing case does not execute. All 6,103
tracked source images remain unchanged through these executions; the actual
Nix source contains 5,049 matching included files and excludes 1,054 others.
The first-failure sequence leaves application-target compilation and the exact
formatter pair unrun.

Read-only source and history review finds the missing witness was not renamed
or superseded. It requires genuine native retirement followed by an accepted
generation containing captured stale Live rows, then verifies that fresh
admission chooses a different pack without reviving excluded placements or
quarantine. Existing ordinary retirement/restore and unauthorized mixed-Live
proposal tests cover different inputs. Both generation-manifest and
store-idempotent-put require this missing witness; their selectors stay intact
while its test-only wrapper, module registration and helper are restored in an
isolated worktree. The separately reviewed Raw durability classifier retains
all fresh observations, duplicate row order and current checks; its ten new
witnesses are registered, but compilation and runtime qualification remain
pending on the composed source. Neither prerequisite accepts a task or closes
the current floor.
The combined `0c771dc7f9` source is reviewed and begins finite qualification.
A separate OBJ-14/15 receiving review confirms that production validates the
manifest's length sum and required BLAKE3 declaration before fetching chunks.
Existing malformed-size tests exercise encoder refusal without actual reader
GET counters. Two additional receiving witnesses are registered in
`derived-attr-record`: independently encoded invalid manifests must be refused
after exactly the manifest GET, with a valid control proving chunk reads occur.
Their current-source qualification remains pending; whole-file plaintext
checksum comparison belongs after chunk reads.
Private `53b4f41b78` now implements both witnesses with independently encoded
wire input, correct identities for those actual bytes and available chunk
bodies. Each requires the typed manifest refusal after one GET and a valid
control that reads every referenced chunk through the same reader. The full
120-line test-only diff is reviewed; stripping it restores the existing tests
exactly. Its 869-line module remains cohesive. Compilation and runtime are
queued behind the combined native qualification. On frozen `0c771dc7f9`, all
three strict Clippy profiles and all three strict private documentation
profiles pass. The original native documentation process clears the shared
Cargo build-directory lock and exits zero without a restart. The native SDK
build also passes; independent review verifies both original exits, exact
commands, log hashes and unchanged 6,105-file source. Actual native test
compilation then passes with a unique nonfresh executable bound to that
source. Discovery includes all 129 required names in the 845-case suite, and
all ten new classifier cases pass with tracing disabled. The restored
stale-Live retirement witness then fails its whole-state comparison at
27.788 seconds: loss generation is three instead of the expected two.
The original run exits 100; the other two retirement cases and all twelve
later stages remain unrun. All post-source and executable checks pass;
independent review verifies 160 retained artifact hashes and preserves a
copy of the actual tested executable. Source review identifies the existing
Raw loss fence when the exact nominal Live placement changes. A reviewed
test-only correction adds that one expected increment while retaining the
complete state comparison and every other assertion. A further source audit
identifies the conditional CAP timestamp successor during independent reopen.
The corrected fixture constructs its complete expected state and logical
projection before reopening, permitting that successor only when the encoded
CAP timestamp changes. Loss generation and every other field remain exact.
Clean combined candidate `13540d1139` includes both retirement corrections,
the two receiving witnesses and the selected graft-admission correction.
Independent review verifies all 6,107 committed file images, modes and symlink
targets. Its finite 39-stage qualification covers strict profiles, actual
compiled inventories, focused regressions, owning gates, application targets
and both formatters. Its first strict Core check exits 101 with E0505 in the
new graft fixture: a vector moves into the entry while the resolved target
still borrows it. Source checks pass before and after the failed command;
all thirty retained artifact hashes match. Stages 2 through 39 remain unrun.
Reviewed test-only correction `1209048a33` clones that vector for the entry,
retaining the target's borrow and every original assertion. Distinct combined
candidate `c789c2b665` proceeds beyond that borrow error, then its first strict
Core check exits 101 with eleven test-only `unwrap_used` diagnostics and one
`explicit_auto_deref` diagnostic. Source checks and all thirty-two retained
artifact hashes pass; stages 2 through 39 remain unrun. A scoped fixture
correction must use the existing test allowance for meaningful `expect`
messages and ordinary field coercion without weakening workspace lints.
Runtime remains pending; neither failed original is retried and no earlier
runtime passes transfer.
Worker corrections replace the test unwraps with meaningful `expect` messages,
remove redundant dereferences and explicitly locate the path-mounted native
test child. Strict Core and native checks pass on that revision. The first
pure refusal witness then exposes an incorrect fixture permission: bit two
is Fork, whereas PROP-16 compares Commit and Admin. Corrected fixtures use
the registered Commit bit four, retaining every refusal and preservation
assertion. Both exact Core witnesses pass with exit zero after compiled
discovery verifies their nonignored names and retained executable identity.
Native discovery then exits 101: the compiler reports that
`CommitContext::property_selection` is absent, although it exists in the
current dependency source and the earlier native Clippy invocation passed.
Native runtime and final-source strict reruns remain unrun. Dependency
artifact reuse is a hypothesis requiring direct evidence, not an established
cause. No cache or timestamp adjustment has occurred, and the original
compiler failure remains preserved.
Direct metadata-only probes now establish an exported API difference under
the same AOS compiler: the retained normal Core library and metadata reject
`property_selection`, while the Clippy metadata accepts the identical call.
All nineteen captured inputs remain unchanged and are archived before later
compilation can replace them. The original Cargo invocation's exact dependency
argument and internal freshness decision remain unproved. Distinct combined
candidate `0dd78ed646` contains the reviewed final fixtures and progress record
at composition; independent review verifies its complete owned source and
ancestry. Its first ten qualification stages pass: strict Core and all
three native-library profiles, private documentation checks, the normal SDK
build and the bound Core test compilation. Stage eleven's discovery command
exits zero and lists 630 Core tests, but the inventory verifier rejects two
required names: they actually belong to `policy::private_registry_tests`,
while the verifier and two Nix definitions use `policy::tests`. Both witnesses
are present once and nonignored. The shared gate selectors are corrected to
the actual module paths; no witness or requirement is removed. The original
failure is preserved, and runtime and owning gates remain unrun. This
qualification is separate from the worker's two scoped Core passes.
Candidate `058f383e7b` composes only those gate selectors and progress updates;
all Cargo inputs remain byte-identical. Corrected discovery reuses the original
actual inventory and compiler evidence. Its two Core graft, two default
receiving, two native receiving, two native graft and three retirement cases
pass. Default compilation also succeeds; a separate observer correction adds
Cargo's declared `default` feature to its expected metadata without recompiling.
Native compilation succeeds and records the actual current Core dependency
and its artifact hashes. The ten new classifier and 110 existing native cases
pass with tracing both disabled and enabled: 240 executions over 120 distinct
names. Together with the eleven receiving, graft and retirement executions,
the current scoped runtime count is 251. Twelve owning checks now pass on the
same actual Nix source: property resolution, required attributes, domain
references, manifest identity, derived attributes, Core without std, native
profile quality, checked mutation publication, written mutation sync, atomic
writes, idempotent puts and index generation. Core without std is compile
only; native profile quality proves three Clippy and three private rustdoc
profiles. Checked publication executes all six exact acknowledgment cases.
Written sync, atomic writes, idempotent puts and index generation execute their
six, twenty-eight, four and fifteen exact cases. Application unit/integration
targets compile across all twenty-nine selected packages, with 112 actual test
artifacts; its package-path observer correction preserves the original failure
and does not replay compilation. Both mandatory format commands pass with
unchanged source. All thirty-nine supporting stages are qualified, including
the explicit source-equivalent reuse of their initial ten stages. Population
cases, ultimate owning gates and the full trunk floor remain pending. No task
checkbox or milestone status advances.
After the class candidate releases the team's heavy lane, the diagnostic's
restoration command exits zero but its artifact verifier stops: Cargo reports
the shared executable as fresh while it still contains the class candidate's
bytes rather than the required earlier executable. Discovery and diagnostic
runtime remain unrun, and the original expected hash is preserved. Read-only
inspection finds the earlier differing source's timestamp predates the shared
relative dependency records, which have checksum validation disabled. This
supports a freshness hypothesis without proving Cargo's internal decision.
The first timestamp command stops on an unsupported option before changing
the file. Its source and inode, mode, ownership, modification and change times
remain unchanged; compilation, discovery and diagnostic runtime stay unrun.
The bare command also resolves through the host PATH. A replacement uses the
explicit AOS coreutils executable and its verified modification-time option.
That finite sequence is authorized with the original executable identity and
non-fresh compiler-artifact requirement retained. Every stopped invocation
remains preserved and contains no diagnostic runtime result.
The replacement timestamp operation and its source/stat checks pass: contents,
inode, mode and ownership stay fixed while the new modification time exceeds
the retained dependency timestamps. Compilation and fresh discovery pass,
binding the original executable and one nonignored case among 832. The single
instrumented 1024-record test then fails in baseline publication after 66.020
seconds. Its actual rejecting sample reports Expired at 30.004481757 seconds
against the unchanged thirty-second writer limit, at `guard/time.rs:270` and
the retained deadline before requests during output synchronization. Source
and original executable checks pass before and after this execution. These
observations identify this diagnostic only; they do not retrospectively explain
the earlier masked denial or establish a speedup.
The diagnostic preserves the thirty-second writer and 120-second process
settings and cannot replace the earlier failed qualification.

The allocation-change qualification now includes all six existing ordinary
and adversarial populations in increasing order, stopping on the first failure.
The current index gate still omits those selectors and retains an explicit
DRV-29 qualification blocker; its prerequisite results cannot stand for those
actual witnesses or permit removing that blocker.

A read-only format audit of `7c71e91bc5` finds no concrete missing current-T1
vector or property implementation. The actual golden gate requires twenty
owning format suites and all 31 assigned reference sections; the fuzz gate
requires 58 public properties and five private encoder properties. These
source coverage findings require current-candidate gate execution before
acceptance. The trunk corrects two descriptive metadata strings to the current
public-case count of 58. Review verifies the unique catalog count and that all
other JSON values remain unchanged; the required inventory is unchanged.

The sealed current floor contains 89 aggregate gates, including all 69 T0/T1
plan-required names and twenty implemented supporting checks. Read-only evaluation
finds `gc-two-phase-delete` explicitly pending. Output validity establishes no
full-floor execution result. No task checkbox, milestone exit or freeze advances.
Current native source still lacks copied-placement preparation and permanent
owner promotion, and recurring permanent residue recovery, required by GC-15,
GC-16 and GC-29. Existing local-v1 checks and pure record validation do not close
those implementation gaps.

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
  The reader stays on its task branch and T-CDC-1 remains open.
  Both actual codec checks also pass on the isolated joint candidate with the
  reviewed reader merged. The native preload consumer and its exact
  paired-publication gate witness are implemented on the task branch.
  Read-only review of the combined candidate confirms dependency-first genuine
  envelopes, verified decoded lengths, every registered dictionary codec and
  fresh source/destination checks. Current joint qualification of all five
  task gates remains required; the earlier serial codec results do not advance
  task completion.
  Reviewed private `7c71e91bc5` adds actual per-class dictionary training to the
  existing authenticated-selection witness, preserving its original assertions.
  Distinct text and shebang corpora are trained with the vendored zstd library;
  classification is computed from plaintext and checked against signed producer
  evidence before selecting the corresponding chunk-domain dictionary. Ordinary
  dictionary fetch and verified decoding exercise the selected bytes. This
  candidate includes the reviewed parent-path buffer prerequisite. Its focused
  witness, whole derived-data gate and all five CDC gates now pass on that
  frozen candidate. Application-target compilation and the exact formatter pair
  also pass; the complete current floor and task acceptance
  remain unqualified.
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
  The native cold-fork prerequisite now additionally requires a thirteenth exact
  witness: genuine older absent-key-7 publication, ordinary full requalification,
  then a separate zero-Node fork. The original twelve-case qualification retains
  its earlier scope; this new compatibility witness remains unimplemented.
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
  A source audit of combined candidate `0c771dc7f95b` identifies another
  PROP-4/PROP-30 admission gap. Changed grafts resolve under the selected
  historical context, then the pure commit validator checks their raw
  overrides using current semantics. The native admission context also omits
  that selected interpretation. Trusted preserve-only bindings can therefore
  be rejected by newer placement or name rules after historical resolution
  accepts them. The shared property-resolution gate now requires two pure
  commit-validator witnesses and two actual historical admission witnesses
  for preservation, publication/rollback and unchanged refusal controls.
  Reviewed implementation `853059704a2f` supplies the selected interpretation
  to the pure commit validator and retains it throughout native admission.
  Current-context callers retain their existing validation behavior. All
  domain, reference, target, administrator, conflict and attribute refusals
  remain in place. The four new witnesses exercise trusted historical
  preservation and actual publication/rollback, with malformed, untrusted
  and unauthorized controls. The production and test diffs are reviewed and
  included in combined candidate `13540d1139`; execution remains pending.
  Current qualified scopes do not prove these additional contracts.
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
  The focused `checks.terrane.integration.native-historical-index-completion`
  check is registered before implementation. Its eight exact cases require
  actual signed historical and Original qualification, whole owner-local I/P/G
  verification, independent per-view attribute inputs and read-only staged or
  stored metadata loading. Existing canonical relationship verification is
  reused. Old attribute-1 interpretation and incomplete missing/conflict
  relationships remain explicit; global configuration cannot substitute for
  a view's actual profile. This historical prerequisite does not qualify
  selected required-index publication or incremental maintenance. Missing
  selectors fail explicitly; implementation and qualification remain pending.
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
  Shared immutable lookup prerequisites now reserve a separate module and
  `integration.index-query` check with three exact candidate-range,
  local-hop occurrence/gap, and divergent-preparation/work-accounting groups.
  The actual check rejects its missing tests after a zero-test run, rather
  than reporting success. The declarations pass core build, strict all-target
  Clippy/rustdoc, both mandatory formatters and the actual no-std gate.
  They add no dependency or format and qualify no lookup implementation.
  Indexed discovery, occurrence traversal and current checks retain DRV-24's
  separate work obligations; the complete normative gates remain pending.
  Review of the isolated lookup candidate required actual cache-search,
  validation, cycle and copy accounting rather than undocumented traversal
  costs. The revised source now separates primary candidates from missing rows
  and compares full typed occurrences and every reported work field against
  independent models of a genuine internal occurrence tree, shared grafts and
  early traversal. All 628 core tests pass with zero skipped, along with strict
  all-target Clippy/rustdoc and both mandatory formatters on the frozen source.
  The actual `integration.index-query` check executes all three exact groups
  once each, then strict Clippy, and passes; the actual no-std gate also passes.
  Every owned source byte remains unchanged through these checks. Candidate
  `a7effc5441bd` remains isolated; current lookup and native index behavior
  remain unqualified by this immutable-data prerequisite.
  Review of the repeatable maintenance candidate finds source-root searches
  over the entire supplied graph, including unrelated roots and an unreported
  no-op owner check. The reviewed shared source prerequisite retains only the
  checked reachable roots and binds their immutable handles into discovery,
  with explicit lookup counters and constant-cost snapshot sharing. Maintenance
  qualification now requires five additional exact source-selection groups
  for unrelated graph growth, retained storage and occurrence contexts,
  geometry/revision refusal, flat snapshot sharing and counter overflow.
  These expand the existing evaluation check to sixteen exact groups;
  declarations alone cannot qualify them. Preserved combined candidate
  `f9e77ddd7bc1` adopts the privately bound source snapshots and passes all 638
  core tests with zero skipped, strict Clippy/rustdoc, both formatters, all
  sixteen exact evaluation groups and the actual no-std gate. Its source
  manifests remain identical through qualification. Source-adoption review
  finds no additional binding, lifetime or algorithm defect. Reviewed correction
  `34b113884e9c` now compares all seven production work fields against independent
  forced split-before/reset and prolonged recovery-to-tail traces, including
  both physical levels, seeks, completion and phase/closure conservation. Its
  full 638-test run, sixteen exact evaluation groups, no-std, strict checks and
  formatters pass without changing production bytes. The additional
  `aos-test-targets` attempt fails because its attribute is absent; that failure
  remains recorded.
  Reviewed verifier correction `43a252ac569b` preserves actual supplied-Node
  decoding and identity hashing separately from measured empty, insertion and
  property reconstruction phases. Repeated contextual visits remain repeated
  work. Lookup borrows the resulting report without cloning its traces.
  Reviewed maintenance correction `a32b077d1780` moves every physical verifier
  field into preparation, separately from retained-tree reconstruction. Its
  gate-selected proof distinguishes eight contextual checks from six retained
  roots and checks empty-root and primary-property phases. All 638 core tests
  pass with zero skipped; actual sixteen-group evaluation, three-group query,
  no-std, strict Clippy/rustdoc and formatters pass. A final comment-only fix
  documents the two retention records per physical tree and passes strict
  rustdoc and both formatters. These reports measure their defined operations,
  excluding CPU instructions and allocator costs. Combined candidate
  `aab21813039a` retains these reviewed changes. Its actual evaluation, query
  and no-std gates bind the final source image and pass, as do both formatters.
  All 5,742 tracked source-file hashes remain identical through qualification.
  The actual `commit-order` gate also passes with the same final source image.
  Its default and keep-going current-trunk aggregates both exit 1. The complete
  failure inventory names `bucket-file-layout`, `dom-dedup-scope`,
  `dom-reference-order`, `feature-matrix`, `index-generation-manifest`,
  `prov-commit-verify`, `prov-disclosure-boundary`, `ref-advance-ordering`,
  `ref-epoch-fencing`, `role-selection` and `store-idempotent-put`. The native
  feature suite reports 377 passing and 28 failing tests out of 405; later
  profiles remain unqualified. The earlier combined candidate reported twelve
  failed dependencies and 362 passing/43 failing native tests. These scoped
  improvements do not qualify the complete native index behavior or T1.
  The common memo audit identified remaining DRV-19 to DRV-22 work: one typed
  memo codec, shared recipe replay/refusal/rebuild and advisory cache behavior,
  actual metadata admission and opaque lookup adapter, and root-associated
  retention/collection. Recipe lookup hashes and immutable memo-object hashes
  remain distinct; generic pack transport and attribute side tables cannot
  substitute for this common mechanism. Current producer/trust checks, native
  index materialization and the complete normative gates remain mandatory.
  The shared canonical Memo codec and `checks.terrane.integration.memo-format`
  now establish the unchanged two-field, 71-byte record before parallel replay
  work. Independently assembled wire bytes and hash preimages distinguish recipe
  lookup keys from immutable record identities; every truncation and explicit
  nonminimal parser witness refuses. All 494 core tests, strict all-target Clippy,
  strict rustdoc, the exact three-group format helper, no-std, the 292-gate registry
  and both mandatory formatters pass. Replay/refusal/rebuild, advisory cache
  behavior, native admission, opaque lookup and root-associated retention remain
  incomplete; this format prerequisite does not qualify `derivation-memo`.
  The shared `checks.terrane.integration.memo-evaluation` helper names nine
  exact replay/cache/rebuild groups before worker implementation. Its requested
  check exits 1 on zero selected tests; a declaration cannot qualify execution.
  The existing metadata validator's common Memo schema arm is separately owned.
  Its shared `checks.terrane.integration.memo-metadata` helper registers four
  exact structural-dispatch groups and exits 1 on zero selected tests before
  implementation. Record validation remains distinct from recipe replay,
  current producer checks and native index materialization.
  The configured metadata validator currently accepts ordinary Node schemas
  only, leaving registered overlay-layer and generic Index Nodes unqualified.
  A shared `checks.terrane.integration.node-metadata` helper names four exact
  structural-validation groups for this prerequisite under STORE-33, TREE-32
  and TREE-35. Accepting registered Node grammar must not infer a contextual
  index role, complete tree relationships, owner binding or current authority;
  the existing owning format decoders and independent repository checks retain
  those responsibilities. A declaration alone does not qualify execution.
  The requested helper exits 1 on zero selected tests before implementation;
  registry completeness and both mandatory formatters pass.
  Reviewed Node metadata candidate `b6843cf880e0` accepts registered ordinary,
  overlay-layer and generic Index schemas through their existing pure decoders.
  Its raw witnesses include exact physical forwarding, primary-gap and
  owner-binding forms without assigning contextual roles or relationships.
  Build, all 134 default-feature tests with zero skips, strict rustdoc,
  Node/Memo/no-std helpers and both mandatory formatters pass. Strict all-target
  Clippy remains red on unowned baseline diagnostics. The newer repository
  policy additionally requires the application test-target compilation check;
  its shared definition and matching policy are now brought onto this branch.
  The trunk compile check and both formatters pass: compiler messages retain
  107 test executables across all 29 application packages, including 70
  integration targets, without executing tests. Joint candidate compilation
  also passes below; its full trunk qualification remains red. The Node
  candidate remains isolated and does not complete T-DRV-2.
  Reviewed common replay candidate `9fadba97815c` passes all 650 core tests
  with zero skips (Nextest run `e67f9315-54a2-4202-8d6c-fe8cbbd25775`),
  strict all-target core Clippy and rustdoc, the nine exact replay groups,
  Memo format, index evaluation/query, no-std and the exact mandatory formatters.
  Replay uses the owning graft/overlay/merge/index algorithms, binds independent
  checked contexts and returns complete owned Node closures. Every cache path
  performs fresh replay; correctly keyed divergence requires explicit rebuild.
  Conflict-base traversal uses an explicit work stack, with a bounded 96-frame
  closure witness. Retained-byte and selected-counter
  reports establish no total replay, copy-work or incremental bound.
  Reviewed metadata candidate `1d738b04d38e` routes the existing Memo kind through
  the common codec, retaining concrete errors under DRV-21 without adding Chunk
  dependencies. All 130 default native tests pass with zero skips (Nextest run
  `a7945ace-e3c7-4cca-bbee-8c98e1f5d389`); its four exact metadata groups,
  build, rustdoc and mandatory formatters pass. Strict native Clippy remains red
  on unowned baseline diagnostics, with no suppression or completion claim.
  Combined dependency candidate `1ce3dbe9f62a` preserves all eight reviewed file
  images. Its actual Memo format/replay/metadata, index evaluation/query, no-std
  and exact mandatory formatter checks pass. Its completed default and keep-going
  current-trunk aggregates both exit 1; the same eleven gate dependencies listed
  above remain red. The first native feature profile records 384 passing and
  25 failing tests out of 409, with no ignored or filtered cases: sixteen
  `Expired`, five `Unsupported`, three `Elapsed` and one `Denied`.
  Later profiles remain unqualified. These components do not qualify persisted
  lookup, complete native admission/producer/coverage checks, root-associated
  retention or collection.
  New combined dependency candidate `7b36c2a5fc11` adds the reviewed Node
  prerequisite and shared application compilation check. All 5,755 tracked
  file images remain unchanged through qualification; all twelve command log
  hashes are independently verified. Its seven owning Memo/Node/index/no-std
  checks and both mandatory formatters pass. The application check records
  compilation of 109 test executables across 29 packages, including 72
  integration targets, without executing tests. Both complete current-trunk
  aggregates exit 1.
  The keep-going run reports ten failed gate dependencies:
  `bucket-file-layout`, `dom-dedup-scope`, `dom-reference-order`,
  `feature-matrix`, `index-generation-manifest`, `prov-commit-verify`,
  `prov-disclosure-boundary`, `ref-epoch-fencing`, `role-selection` and
  `store-idempotent-put`. Its first native feature profile records 387 passing
  and 26 failing tests out of 413, with no ignored or filtered cases:
  eighteen `Expired`, five `Unsupported` and three `Elapsed`.
  Later profiles remain unqualified. Required disclosure witnesses remain
  missing or unqualified; diagnostic timing observations do not qualify them
  or justify changing the mandatory checks.
  The next repository prerequisite loads the independently selected owner's
  namespace and exact I/P/G closure through immutable `ContentStore` reads,
  then supplies the existing pure relationship verifier and query preparation.
  A shared module and `checks.terrane.integration.index-loading` register four
  exact groups for read-only loading, independent physical/contextual checks,
  unavailable evidence and divergent relationships with separate work reports.
  The declaration's requested check exits 1 on zero selected tests; registry
  completeness, both mandatory formatters and the application compilation
  check pass. Loading must preserve raw identity, physical placement, semantic
  roles and expected source roots separately under DRV-25/27/30, TREE-35 and
  PROP-31. Byte caching cannot remove contextual or repeated-occurrence checks.
  Current producer/trust/authority checks, same-commit maintenance, corrected
  owner commits and the positive native safe-index case remain separate
  obligations. This declaration does not qualify implementation.
  No formal task merge, checkbox or milestone freeze advances.
  The reviewed unpublished loader candidate `b8728e93cfbb` implements the
  immutable loading prerequisite through Node-only whole `get` calls. Raw
  identity, root/internal placement, semantic carrier roles and independently
  selected source roots remain distinct; shared bytes suppress only repeated
  reads. Caller-owned source reconstruction checks physical child geometry and
  exact canonical bytes before complete pure owner-to-I/P/G verification and
  query preparation. Loading, reconstruction, preparation and query work have
  separate reports; these event counts do not claim total or incremental cost.
  Independent review required and verified internal primary/gap-tree witnesses,
  isolated summary corruptions and exact independently enumerated loading and
  reconstruction reports. The final source also checks an empty unbound owner
  as typed incomplete evidence. All five reviewed file images match the final
  owning-check and application-compile source. Four exact loading groups pass
  one case each with no ignored cases; the full default-feature Nextest run
  `1df0c59c-2534-4dd4-adfa-59d8389f97ce` passes 138 tests with zero skips.
  Nine existing Node/Memo/index/no-std checks, both mandatory formatters, build
  and strict rustdoc pass in their recorded source scopes. The application check
  records compilation of 109 test executables across 29 packages and 72
  integration targets without execution. Strict all-target native Clippy remains
  red with 36 library and 16 test errors outside the five loader files; no
  suppression was added. The implementation is assembled only in unpublished combined
  candidate `9ec056b4f8b3`; formal task merges remain withheld while the full
  trunk floor is red. Current producer, authority and trust checks, complete
  coverage decisions, Memo runtime integration, same-commit maintenance,
  corrected-owner rebuild/publication and positive native safe-index
  materialization remain incomplete. No task or milestone status advances.
  Completed combined qualification of `9ec056b4f8b3` passes both mandatory
  formatters, the owning loader check and application compilation (109/29/72,
  without execution). All 5,761 tracked file images remain unchanged and the
  six command log hashes are independently verified. Default and keep-going
  current-trunk aggregates both exit 1. The same ten gate dependencies listed
  above fail; the first native profile records 391 passing and 26 failing tests
  out of 417, with none ignored or filtered: seventeen `Expired`, five
  `Unsupported`, three `Elapsed` and one `Denied`. Later profiles and required
  disclosure witnesses remain unqualified. No timing cause is inferred, no
  mandatory check is changed, and no formal task merge or freeze advances.
  The next native common-Memo prerequisite consumes explicitly selected,
  untrusted immutable Memo addresses and optional claimed output-Node addresses
  through read-only `ContentStore` operations. Only actual fetched bytes may
  populate the existing common advisory table. The same evaluator must replay
  the original recipe and mandatory inputs once, compare the complete claimed
  closure, retain typed storage subjects/causes separately from advisory status,
  and preserve divergent refusal or explicit same-evaluator rebuild. Disabled
  caching performs no advisory reads. Neither invented recipe identities nor
  opaque notes decoded as commit pointers may supply an association. Durable
  selection, publication and root-associated collection remain separate.
  Shared `checks.terrane.integration.memo-replay` declares four exact groups;
  zero selected cases must fail rather than qualify this prerequisite.
  Its requested declaration check exits 1 after reporting zero selected cases.
  Registry completeness, both mandatory formatters and application compilation
  pass; the latter records compilation of 107 test executables across 29
  packages and 70 integration targets without execution. These results qualify
  shared declarations only.
  Reviewed unpublished native Memo candidate `db6b1feb9d9f` implements the
  selected immutable replay prerequisite. Actual fetched Memo and Node bytes
  seed the existing common RAM association. One unchanged mandatory replay
  preserves original recipes and inputs, complete claimed-output refusal,
  typed divergence and explicit rebuild through the same evaluator. Both result
  branches retain original storage subjects and source diagnostics; checked native
  loading counters remain separate from semantic evaluation and query work.
  Independent raw graft, whiteout overlay, plain merge and bound hierarchical
  index fixtures cover complete inventories, valid extra/excluded Nodes,
  mandatory error subjects and all four loading-counter overflow paths.
  All four final source images match the actual owning and application compile
  source. The four exact owning groups each pass one case with no ignored
  cases. Full default native Nextest run
  `f4a24252-da61-496b-b156-892346650ea8` passes 142 tests with zero skips;
  build, strict rustdoc and both mandatory formatters pass. Recorded existing
  loader and core Memo/metadata/no-std checks keep their separate source scopes;
  all 276 core file images remain unchanged. The application check records
  compilation of 109 test executables across 29 packages and 72 integration
  targets, without execution; its output preserves compilation records and
  platform metadata. Strict native Clippy remains red on 36 library and 16 test
  diagnostics outside the four owned files. Owned diagnostics were corrected
  without suppression, and original failed attempts remain recorded.
  Completed qualification of unpublished combined candidate `15540ef204ec`
  passes both owning checks, application compilation and both mandatory
  formatters. All 5,766 tracked file images remain unchanged; all seven command
  log hashes are independently verified. Default and keep-going current-trunk
  aggregates both exit 1. The default run fails at physical-exclusion admission
  in `index-generation-manifest`, returning `Unsupported`. The keep-going run
  reports eleven failed gate dependencies: `bucket-file-layout`,
  `dom-dedup-scope`, `dom-reference-order`, `feature-matrix`,
  `index-generation-manifest`, `prov-commit-verify`, `prov-disclosure-boundary`,
  `ref-advance-ordering`, `ref-epoch-fencing`, `role-selection` and
  `store-idempotent-put`. The first native feature profile records 396 passing
  and 25 failing tests out of 421, with none ignored or filtered: sixteen
  `Expired`, five `Unsupported`, two `Elapsed`, one `Denied` and one
  `WouldBlock`. Later profiles and required disclosure witnesses remain
  unqualified. These observations do not establish timing causes; no mandatory
  check is changed.
  Durable association selection, current native serving, producer, trust and
  authority checks, completed index owner maintenance/publication and DRV-19
  root-associated collection remain incomplete. No formal task merge, checkbox
  or freeze advances.
  A source audit confirms that ordinary maintenance emits the selected
  `index-roots` wrapper and a binding transition without constructing the
  property-mutated owner. DRV-25/26 require the acyclic construction step:
  independently check selected I/P/G data against candidate entries, preserve
  unrelated owner properties and bindings while producing owner R, then form
  detached Q/q and optional unchanged common Memo records from R. Selected
  immutable associations do not establish current coverage or publication;
  missing inline values remain gaps, and retained maintenance snapshots remain
  bound to their original source until separately prepared for R. Shared
  `checks.terrane.integration.index-completion` now declares five exact groups
  for initial binding, preservation, divergent binding replacement, refusal
  and post-binding common Memo/work separation. The requested declaration
  check exits 1 with zero selected tests. Registry completeness, core no-std,
  application target compilation and both mandatory formatters pass; the
  four declared file images match all three actual compilation/check inputs.
  These results qualify shared declarations only. Full verification, property
  mutation, arena allocation and graph copying must remain separate from
  DRV-29's incremental accounting. No task checkbox or milestone advances.
  Reviewed unpublished completion candidate `89249c84fd89` implements that
  ordinary immutable construction step. It independently prepares the source
  and verifies each selected exact I/P/G closure, merges owner-local bindings
  while preserving unrelated properties and unselected bindings, and forms
  detached recipes and optional common Memos only after verifying the completed
  owner's actual binding. True no-op completion reuses the original root;
  otherwise unchanged physical descendants remain shared. Retained maintenance
  snapshots keep their original source owner, and missing inline values remain
  gaps. Independent raw owner/index/recipe/Memo witnesses exercise actual
  initialization, explicit divergent-binding rebuilding, property-only updates,
  zero candidates with gaps, refusal limits and separately scoped work counts.
  All fourteen final validation commands pass on the unchanged four-file source:
  full core Nextest run `79a70abc-29d0-4d0a-bc86-39ad65c78355` passes 655 tests
  across seven binaries with zero skips; build, strict Clippy/rustdoc, six
  immutable index/Memo/no-std checks, application compilation, both mandatory
  formatters and diff checking pass. All seven actual Nix check/compile inputs
  match the reviewed source images. The application output records compilation
  of 109 test executables across 29 packages and 72 integration targets, without
  execution. The original validation driver's metadata parsing failure remains
  recorded; inspection resumed without repeating passed checks. Parent combined
  checkout `0ff3e24db5d1` and native source checkout `3578e7216bdd` now retain
  this reviewed dependency. Their joint qualification remains pending; no
  implementation is merged into the published trunk and no task checkbox,
  milestone exit or freeze advances.
  A separate source audit confirms that native initialization and loss rebuild
  cannot acquire ordinary namespace inputs through the bound-index loader:
  it discards its fetched namespace when the owner binding or auxiliary index
  is absent. Public snapshot/file projections do not expose a reusable ordinary
  namespace graph. The next native prerequisite factors the existing reader's
  namespace phase and canonical reconstruction into source-only acquisition;
  it must preserve the strict bound-index loader and must not expose private
  authority witnesses or follow auxiliary bindings. Shared
  `checks.terrane.integration.index-source` declares four exact nonzero groups
  for unbound input acquisition, repeated graft/internal physical contexts,
  typed source failures/revisions and actual initialization/loss-rebuild
  consumption. Its requested declaration check fails on zero selected tests.
  Registry completeness and both mandatory formatters pass; both declared
  images match the actual owning check input. Source acquisition supplies
  mandatory immutable inputs, not current producer checks, publication or
  complete native rebuild qualification. T-DRV-2 and T1 remain open.
  Reviewed unpublished native source candidate `8dfcb67c8f1c` factors the
  shared reader's namespace phase into read-only acquisition independent of
  index availability, retaining canonical reconstruction, selected revisions,
  geometry and original typed errors. Strict bound-index loading still refuses
  missing or divergent auxiliary evidence. Four exact owning groups exercise
  unbound sources, repeated graft/internal contexts, failures/revisions and
  genuinely fetched initialization and explicit loss/divergence rebuilding.
  The latter feeds actual materialized I/P/G into reviewed owner completion
  and checks completed owner, recipe and optional common Memo bytes against
  independent encodings, including zero candidates with retained gaps. It
  establishes no current producer, trust, authority or publication proof.
  Its unchanged eight-file source passes native build, all 146 default tests
  with zero skips, strict rustdoc, four assigned Nix checks, application
  compilation and both mandatory formatters. Strict native all-target Clippy
  exits 101 with 36 library and 16 test diagnostics outside those files;
  no diagnostic is suppressed. Original failed attempts remain preserved.
  Parent combined candidate `21981e66f440` passes both mandatory formatters,
  `index-completion`, `index-source`, `index-loading`, `memo-replay`,
  `core-no-std` and application compilation. All 5,775 tracked images remain
  unchanged through its ten original commands; six successful check/compile
  inputs and the failed feature-matrix input match all twelve reviewed files.
  Both aggregate commands finish and exit 1. The keep-going inventory reports
  twelve failed dependencies: `bucket-file-layout`, `commit-order`,
  `dom-dedup-scope`, `dom-reference-order`, `feature-matrix`,
  `index-generation-manifest`, `prov-commit-verify`,
  `prov-disclosure-boundary`, `ref-advance-ordering`, `ref-epoch-fencing`,
  `role-selection` and `store-idempotent-put`. The first native profile passes
  378 and fails 47 out of 425, with none ignored or filtered; later profiles
  remain unqualified. Physical-exclusion admission returns `Unsupported`;
  the `commit-order` attribute case returns `Expired`. These observations do
  not establish causes. Thirteen T1 tasks and the pending `derivation-memo`,
  `index-tree-maintenance` and `algebra-fork` gates remain open; pending gates
  are outside this aggregate inventory. Implementations remain unpublished;
  no formal task merge, checkbox, milestone exit or freeze advances.
  The isolated common Memo implementation now passes its 23-case owning
  `derivation-memo` Nix check. Separate exact runtime selections pass 12 core
  cases and 11 terrane cases in each default, std/send and tokio/SDK profile;
  strict Clippy, private rustdoc and both mandatory formatters also pass.
  The original reporting failure remains preserved: Nextest suppressed individual
  PASS lines, while its exact inventories, completed summaries and owning
  per-case logs establish these scoped results. No unrelated tests or whole-task
  completion are inferred. D-110 separately records the missing per-view used
  interpretation needed for eligible cold reuse and source carry. Its optional
  ordinary-data context preserves old encodings; absent context requires normal
  full admission and fresh lineage before no-walk reuse. The ordinary context
  codec now passes eleven exact `consumed-view-context` integration cases and
  all 488 core tests on the trunk. Strict core Clippy, no-std compilation,
  private rustdoc, default/std-send/tokio-SDK compilation and both formatters
  pass; the existing 39 publication vectors and ten model cases remain green.
  PROP-30 requires exact registered property vocabularies and rejects unknown
  property revisions independently of execution support. Existing producers
  still record absent context. Genuine capture, current-selection comparison,
  index qualification and cold/source-carry checks remain unqualified.
  A separately composed native producer now captures each actual consumed-view
  interpretation only after successful owning history verification or closed
  admission. Six actual native cases pass: published candidate context,
  completed Recorded history, missing Original association refusal, required
  index refusal before its owning validator exists, refusal to relabel Legacy
  admission and exact revision-one vocabulary. All 666 core tests and eleven
  context cases pass on the same frozen candidate, together with fourteen
  stopped-Session and held/output-sync regressions. Strict native, default and
  Send Clippy, no-std compilation, private rustdoc, the context/publication/model
  Nix checks and both formatters pass. The first attempt's malformed property
  fixture and native borrow errors remain preserved; two test-only corrections
  precede this successful run. Existing private property and attribute profiles
  remain intact. Required index completion, tracked Recorded disclosure,
  independent cold reuse and source carry remain incomplete. This candidate is
  isolated and unpublished; it does not qualify the full trunk gate set.
  The reviewed historical-index candidate `1ef4500bb29e` passes all eight exact
  native relationship cases with none ignored. Its corrected five-file source
  passes strict all-target Clippy and private rustdoc in actual default, std/send
  and native Tokio/SDK configurations, application compilation and both mandatory
  formatters. Application output independently records 111 test executables
  across 29 packages, including 74 integration targets, without execution.
  All 4,844 owning-check inputs and 4,847 quality/application inputs match their
  frozen snapshots; only six shared metadata paths differ between these runs.
  The original first-case missing association, 41 owned assertion-style lint
  errors and mislabeled extra no-default-feature errors remain preserved.
  Explicit test matches retain original typed refusals and wire assertions;
  genuine repository reopening loads retained Original associations.
  Local integration candidate `5c09eaa8f0ac` assembles these qualified
  prerequisites with exactly the same tree and all 5,901 reviewed file images.
  It remains unpublished. No current-index publication, lookup coverage or
  incremental-maintenance claim follows.
  A source audit identifies the next shared prerequisite: independently select
  authoring semantics before signing, then retain the successful admission's
  exact view/root interpretation through candidate recording and post-staging
  history. Existing historical views retain their own installed selections.
  Initial requirement installation and preserved gaps must remain successful
  incomplete outcomes under PROP-22/25; they cannot excuse dropping an actual
  valid maintained binding under DRV-27/29. Constructor-only profile changes
  cannot replace an existing protected Guard installation.
  `checks.terrane.integration.native-index-publication` declares eight exact
  native groups for those prerequisites under DRV-25/27/30 and PROP-30.
  Missing, ignored or unexecuted witnesses must fail explicitly. Declaration
  does not qualify implementation, current coverage or DRV-29's cost bound.
  The declaration's requested Nix check compiles, then exits 1 naming all eight
  missing witnesses. Registry completeness and both mandatory formatters pass.
  `checks.terrane.integration.native-profile-quality` separately checks strict
  all-target Clippy and private rustdoc in actual default, std/send and native
  Tokio/SDK configurations. Its hermetic target permits independent review
  while a worktree's shared incremental target runs tests. No runtime case or
  feature-matrix completion follows from lint and documentation checks.
  Its initial trunk run exits 1 in actual-default Clippy with 37 library and
  22 test diagnostics on unfinished integration. Later profiles and rustdoc
  do not execute; no suppression or profile success is inferred.
  A further pure prerequisite is declared as
  `checks.terrane.integration.mixed-view-interpretation`: eight exact cases
  require independently selected Legacy and Recorded views in one disclosure
  history, exact original-root association, inert revision-one names, strict
  missing association refusal and unchanged scope verification. The installed
  base and exact overrides are ordinary configuration under PROP-30 and
  PROV-4/7 to PROV-10/16; they supply no original authority or coverage.
  The existing uniform constructors must remain compatible. Missing witnesses
  fail explicitly; declaration alone qualifies no implementation or task.
  The declaration's initial Nix run compiles, then exits 1 naming all eight
  missing cases. Registry completeness and both mandatory formatters pass.
  The isolated mixed-view implementation now passes all eight exact cases,
  including genuine complete disclosure with Legacy and Recorded-1 ancestry.
  Its full Core run passes 674 of 674 tests with none skipped; strict all-target
  Clippy, private rustdoc, no-default compilation and both formatters pass.
  Application qualification compiles 111 executable targets across 29 packages
  and 74 integration targets without running them. Both actual Nix inputs match
  all 4,852 included tracked files. Earlier compiler and fixture failures remain
  preserved; the positive Recorded-1 fixture uses a valid inert binding that
  also passes the unchanged enclosing Recorded-3 comparison. Production
  verification does not change to accommodate those fixture failures.
  The reviewed nine-file source is preserved locally at `3ae281e69e65`.
  Independent attribute-profile and captured-selection helpers separately pass
  strict native/default/Send quality and all eight historical-index cases at
  `649446a0e8a8`. Authoring admission and publication remain unfinished.
  The isolated executed-view lifecycle is now preserved at `d8aef83d75`:
  closed admission supplies its exact signed view/root and independently
  selected profile through staged history and genuine mixed disclosure.
  Recorded meanings survive later operations and metadata adapters; Legacy
  defaults are not cached as overrides. Strict Clippy and private rustdoc
  pass for actual default, std/send and native profiles. Its original
  replacement fixture fails at the earlier real `guard-install` refusal;
  the corrected fixture checks that refusal and the unchanged protected
  state. All three exact authoring cases subsequently pass in a private
  hermetic check, including two successive Recorded publications. Portable
  Terrane compilation passes with twenty warnings, without a strict
  no-default-profile lint claim. The separate same-invocation read-history
  reuse prerequisite at `62a7a4d9fe` preserves current authority, scope, token,
  domain and trust checks. Actual native Nextest runs all seven authoring and
  Recorded-history cases successfully, with 569 deliberately filtered cases;
  UUID `5cd9e4dd-cee6-42c6-a916-4e3525df5f0c` takes 64.435 seconds.
  Strict default/Send/native quality and both formatters pass on that source;
  both private hermetic inputs match all 4,855 included files. The preceding
  Recorded owning check passed two cases, then returned `Expired` in its third;
  its fourth did not execute. That failure remains preserved. The owning
  check on the new read source now passes all four exact cases; its input is
  the same independently checked 4,855-file source. Required inline Index
  admission, lawful initial/preserved binding gaps and actual pre-signing
  incremental I/P/G maintenance remain separate unfinished writer obligations.
  The locally preserved merge-selection correction at `e147f58219` uses actual
  completed view selection and passes its three existing exact native helper
  cases, strict three-profile quality and both formatters. This supplies no new
  genuine Recorded merge or cold-fork qualification. The ordinary full-profile
  comparison prerequisite at `6a211f715e` retains independently selected
  namespace inputs without selecting configuration from decoded lineage.
  Existing verified consumers retain their signed-root and physical-profile
  checks. Fifteen exact existing authoring, historical-index and Recorded-history
  cases pass, as do strict three-profile Clippy/private rustdoc and both
  formatters. Both hermetic inputs match all 4,855 included file images;
  a subsequent documentation-only correction clarifies the selection boundary.
  The isolated native writer additionally passes all eight exact
  `native-index-publication` cases on unchanged source preserved at
  `f4ae2b17c3`. Its actual input matches all 4,861 included images.
  Cases cover publication and full carriers, incremental maintenance, typed
  divergence and dropped-binding refusals, lawful missing-value gaps, backfill,
  inert historical attributes and independently configured reopening.
  Work reporting separates retained/staged input acquisition, real delegated
  store calls, reconstruction, verification and maintenance; it does not claim
  total publication I/O. After composition with the shared view helper, all ten
  focused native cases pass with zero skipped in 76.592 seconds, UUID
  `d48f2742-19f5-46e1-83c4-a162f0ac34a6`. Separate owning publication and
  historical completion checks each pass all eight selectors on independently
  matched frozen input. Application qualification compiles 111 test executables
  across 29 packages; it executes none. Strict native Clippy refuses only a
  complex test return type; default/Send Clippy and private rustdoc pass.
  A separately preserved equivalent tuple alias and formatter correction
  change no test bodies or assertions. Strict three-profile Clippy/private
  rustdoc and both formatters pass on that final source, with all 4,861 actual
  included inputs independently matched. Earlier runtime successes retain
  their explicitly pre-alias scope; the complete trunk floor remains pending.
  These local prerequisites do not close a task or
  qualify the full current trunk gate set.
  Shared module registrations now reserve independent native indexed-read and
  common Memo persistence leaves at public `guard::indexes` and
  `derivation::persistence` paths. Their owning integration checks require six
  and four exact, nonignored cases respectively; absent implementations fail
  discovery explicitly. Registry completeness and both formatters pass on the
  registration-only source. This supplies no indexed-answer, persisted Memo,
  root-associated GC or full trunk qualification.
  A separate conditional Memo-retention check requires one exact native witness
  for independently live output Nodes, orphan claims, recipe-key nonedges and
  live Chunk nonedges in full and witness traversal. Its parent composition draft
  preserves current selected observations and introduces no recipe or content
  roots. The preservation candidate `cddf9c906a77`, composed at `1b5dfbfee174`,
  now passes its exact owning native Nix witness, strict all-target Clippy/private
  rustdoc in default, Send and native profiles, and three existing Attribute/
  witness traversal regressions. All three actual hermetic inputs match the same
  4,877 frozen files. Its exact focused native Nextest case also passes with zero
  skipped selected cases. Inspection never roots a Memo claim or recipe key;
  matching records retain genuine Node proof positions without introducing Chunk
  edges. This bounded prerequisite does not close DRV-19 or the derivation gate.
  The native persistence candidate `0090d143d50d` now passes all four exact
  owning cases with zero failures or ignored tests, followed by strict all-target
  Clippy and private rustdoc in default, Send and native configurations and both
  mandatory formatters. All 4,878 actual hermetic input files independently match
  the frozen source. These witnesses cover durable Memo/output reopening,
  advisory loss, divergence/rebuild and genuine current/Original/trust checks.
  The composed candidate `1bb5aa60d39a` additionally passes the required default
  package build, fresh default Nextest discovery and all 157 default tests with
  zero skipped, application test-target compilation and both formatters. Its
  actual application input independently matches all 4,893 frozen files; the
  three persistence images remain unchanged. This default suite executes no
  native witnesses. Broader root-associated GC remains open.
  The shared normative `derivation-memo` gate now requires the twelve common
  codec/evaluation cases and eleven immutable loading/metadata cases together
  with the four actual native persistence cases and conditional-retention
  witness. All three inventories and all 28 exact positive executions are
  mandatory. Missing implementations fail discovery. The composed candidate
  `d11adeabde58` passes the complete 28-case gate with zero failures or ignored
  selected tests. All 4,893 actual hermetic input files independently match the
  frozen source, and core/default/native discovery contains 598/157/613 tests.
  This local gate result does not qualify an implementation merge on the trunk.
  T-DRV-2, ALG-32, task merges and T1 remain open.
  The next native prerequisites explicitly require checked verification/rebuild
  (DRV-16/17/25) and metadata-only checked side-record backfill (DRV-28).
  Shared module declarations and owning checks now require three rebuild and
  four backfill witnesses before their isolated implementations begin. Missing
  witnesses fail discovery. These declarations establish no implementation or
  gate pass; native recovery, backfill and expanded maintenance remain open.
  The parent-first backfill prerequisite extracts the existing authenticated
  producer-history/current-readable-occurrence checks without changing their
  authority or refusal behavior. A test-only Chunk attempt counter follows the
  real bucket, clone and held adapters. All five exact observation calibration
  cases, application test-target compilation and both mandatory formatters pass;
  all three actual build inputs match the same 4,557 frozen files. Strict
  default Clippy fails with 37 library and 22 library-test errors in unchanged
  prerequisite files; later profiles and private rustdoc remain unqualified.
  The finite backfill implementation, composed quality checks and complete
  index-maintenance gate remain pending. No task or milestone status advances.
  The isolated native backfill first fails compilation, then exposes a fixture
  self-lock from an ordinary clone read while an exclusive holder is live.
  Both original attempts remain preserved. After the owned compile and lock-order
  corrections, the actual 632-test inventory contains all four witnesses;
  the first runtime refuses commit on refs/heads/_/main with zero passes.
  Remaining runtime cases and quality/application checks are unexecuted. Genuine
  request and authorization tracing remains pending; no grant is widened.
  The reviewed unchanged-owner producer subsequently passes the exact native
  reuse and evidence-gap cases. Its original current-policy negative used
  Admin plus Commit, which lawfully authorizes publication under AUTH-22.
  After correcting that fixture to Read only, reuse and gap cases again pass,
  while the current/final case returns `Absent(Commit)` in 31.78 seconds.
  The fourth case and later quality/application checks remain unrun. Independent
  review verifies all 50 preserved artifacts and 4,911 actual Nix source inputs.
  The error alone does not distinguish body absence from PROV-15 trust masking;
  a separate diagnostic must identify the actual failing stage and Commit role.
  The isolated backfill subsequently preserves physical Commit presence while
  exercising the exact policy-masked absence, and offers one final catalog
  variant for each evidence-gap refusal. Its fourth fixture initially violates
  TREE-17's ascending entry order; sorting only that fixture repairs construction
  without changing its native completeness assertions. Frozen `8fed7955e56a`
  passes reuse, evidence-gap and current-policy cases, then the completeness case
  returns `Advance(Expired)` in 55.97 seconds. Historical, quality, application
  and formatting checks remain unrun. Independent review verifies all 54
  preserved artifacts, 4,911 actual Nix input images and 5,965 frozen inputs.
  An owned-only trace first fails compilation in the shared Cargo target, before
  execution. Its separately qualified private Nix input compiles the actual Core
  source and executes only the same completeness case, which returns
  `Advance(Expired)` in 50.82 seconds. The trace brackets 30.05 seconds between
  candidate-evidence completion and scope exit, with no durable-upload marker.
  This measures the upload-loop interval, without identifying an individual
  put, syscall or the earlier failure's cause. All 32 original artifacts,
  4,911 actual input images and 5,965 frozen inputs are independently verified.
  The diagnostic is then restored byte-for-byte in a normal commit. The private
  source adopts the separately qualified physical-predicate coalescing while
  preserving its pair checks. Frozen `4d451aafc23d` passes all eight actual
  physical-predicate/exclusion regressions and the reuse, evidence-gap and
  current/final owning backfill cases, with exact discovery among 636 tests and
  zero ignored cases. Completeness still returns `Advance(Expired)` in 50.80
  seconds; historical, quality, application and formatting checks remain unrun.
  Independent review verifies all 74 preserved artifacts, both derivations'
  4,912 actual source inputs and 5,966 unchanged tracked byte/executable/symlink
  images. Coalescing has not established an expiry fix or completed DRV-28.
  The private placement/Raw prerequisite on frozen `6f349fb064` passes four
  exact Raw durability groups and nine existing regressions, each independently
  discovered among 640 native tests with zero ignored cases. Genuine faults,
  cancellation and incarnation replacement retain the real acknowledgment
  assertions. Reopen checks permit only the independently verified normal
  capability-probe successor. Independent review verifies all 108 preserved
  artifacts, three derivations' 4,916 actual inputs and all 5,970 committed
  images. Strict quality then stops in default at the backfill facade's missing
  concrete store Sync bound; later checks are unrun. The reviewed one-line bound
  resolves compilation, exposing three ordinary editor Clippy findings. Their
  equivalent idiom corrections are reviewed separately. The seven placement
  witnesses and complete backfill/history qualification remain outstanding;
  these Raw results do not complete DRV-28 or T1.
  Frozen private `638bad375f` passes strict all-target Clippy and private rustdoc
  for default, Send and native profiles, application test-target compilation and
  both required formatters. The owning backfill gate runs all four exact cases
  among 640 native tests with zero ignored cases: reuse, evidence gaps and
  current/final checks pass; completeness returns `Advance(Expired)` in 43.64
  seconds. Historical completion remains unrun. Independent review verifies all
  91 preserved artifacts, three derivations' 4,916 actual inputs and all 5,970
  unchanged committed images. These results preserve the failure and establish
  neither an expiry fix nor complete backfill qualification. The earlier thirteen
  Raw/current regression successes belong to their separately frozen source.
  The owning index gate now registers all six native 1,024/2,048/4,096-entry
  ordinary and adversarial batching/resynchronization witnesses. The explicit
  DRV-29 blocker remains until their execution is reviewed; registration and
  lazy derivation evaluation do not qualify maintenance or complete this task.
  On frozen `058f383e7b`, the first ordinary 1,024-entry workload fails during
  baseline publication with `Advance(Expired)` after 59.04 seconds, before
  maintenance begins. Source and executable remain unchanged. The five later
  workloads and memo check remain unrun. One separate instrumented diagnostic
  on that unchanged source also fails: its native deadline sample is
  30.007576264 seconds against the unchanged 30-second maximum, at
  `outputs-file-after-refresh` during final output synchronization. The 233
  outputs are the required 232 generation shards and MANIFEST, not separate
  metadata packs. Private parent-owned change `331b2fd87d` preserves physical
  checks and native acknowledgment while incrementally reclassifying only
  successfully rebound or consumed paths. Independent source parity review and
  scoped formatting pass. A separate private parent change `bceb6b16ea` reuses
  lexical ancestor-path capacity across named fences; independent review
  confirms unchanged leaf, ancestor and descriptor checks and refusal order.
  Regression coverage, compilation and timed workload qualification remain
  pending for both native changes. No deadline or output layout changes.
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
- [ ] **T-BKT-1** `bucket` backend over `file://`: key layout, mutability
  classes, atomic writes, filesystem CAS, generation manifests, startup
  probe. Conformance is reopened for STORE-4: the existing ranged getter reads
  the whole pack before slicing. Bounded framing/index/member reads and an
  actual no-whole-pack I/O witness remain required; previously passing slice
  and overflow checks do not qualify that requirement. D-77's version-2 ref
  and migrated-log leaves preserve nested ref names;
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
  genuine unchanged-bound qualification remain required. That candidate's
  twelve aggregate failures remain unresolved in its retained qualification.
  A subsequent read-only audit binds `aab21813039a`'s actual compiled image
  to all 28 native failures and eleven aggregate dependencies. Twenty of its
  21 `Expired` cases fail initial advances; one fails prepared publication.
  Four `Unsupported` cases change retirement associations through an existing
  refusing raw route; the fifth attempts writable reopen of a payload copy
  lacking its destination's physical registration. Three required native
  provenance witnesses are absent. These causes and early failure locations
  remain distinct from unmeasured timing phases; no deadline, factory boundary
  or mandatory positive case is weakened by the audit.
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
  The shared test-only counted read boundary is pushed at `d00ec63cee`.
  It preserves existing post-body gates and permits a fixture to pause an
  actual artifact read after a measured genuine repair prefix. All 45 exact
  `bucket-file-cas` and three `native-content-observation` cases pass, as do
  both formatters. The separate held-upload draft passes its three existing
  store gates and application compilation, but all four new witnesses fail
  during setup because they incorrectly assume a filter exists. Corrected
  fixtures must distinguish real selection/repair reads and mandatory repair
  synchronization from later direct artifact verification; no production
  verification or repair condition is relaxed.
  The corrected filtered-generation fixture passes the same three store gates
  and application compilation on independently matched source. Its four new
  runtime cases still fail during setup: a plain Filter body correctly violates
  STORE-33's canonical-CBOR requirement. None reaches its behavior assertions.
  The reviewed fixture correction preserves that typed refusal and supplies
  independently encoded canonical Filter data. The next runtime passes three
  cases, then refuses the fourth fixture's attempted overwrite of an immutable
  corrupted row. The reviewed fixture distinguishes actual missing-row repair
  from the required typed refusal of a present conflicting immutable row.
  All four unchanged-production native witnesses then pass in 8.763 seconds,
  UUID `13bdabb9-0889-44ed-8a03-bba8d733255b`, with zero ignored cases.
  The measured fixture reduces metadata/dispatch/GET counts from
  3044/1047/116 to 2146/795/90 and selected reads from 63 to 45, preserving
  both mandatory repair effects. These are scoped fixture observations.
  All 156 default tests and strict native/default/Send Clippy/private rustdoc
  pass. Final independent owning store checks execute 1/3/12 cases and pass,
  along with application compilation and both formatters. All four actual Nix
  inputs independently match the same 4,856-file source. Full production and
  fixture review preserves earlier failed attempts and distinguishes the
  capture-only log-path error from successful test execution. The exact
  fixture correction is preserved at `3c3d51b5b5` and locally composed for
  future trunk qualification. No task or full-floor result is inferred.
- [ ] **T-GC-1** Mark-and-sweep collector: roots, mark, grace, two-phase
  sweep, singleton lease, resumability, retention values `gc`, `lease`,
  `ttl`, `forever`, and ordinary reflog duration/count selection.
  Parent-owned registrations and a nineteen-case auxiliary check now prepare
  isolated implementation of genuine local copied-destination first ownership.
  D-113 clarifies truthful conservative DATA roots/state at the existing
  pointers without encoding changes or foreign retention/lineage certification.
  Separate parent-owned registrations and an eleven-case auxiliary check prepare
  permanent local residue recovery and restoration through fresh secure IDs.
  Its checked owner and current copied-placement fence must bind the same actual
  held selection and lease; neither carrier alone permits native reclamation.
  Its production modules and runtime qualification remain pending; recurring
  permanent recovery and restoration remain additional T1 local obligations.
  The current `gc-two-phase-delete` gate now requires ordinary local conformance
  with its complete prerequisite closure, copied first ownership, and permanent
  local reconciliation from the same package source. Lazy evaluation succeeds;
  the new runtime paths remain unqualified and this task stays open. T3 must
  extend this local T1 aggregate with actual provider conformance.
  D-114 separates a recurring pass's genuinely current collection fence cycle
  from its immutable original owner/event-key cycle. CreateOnce roots and all
  actual current qualification remain mandatory; changed roots use a genuine
  fresh collection cycle. On private prerequisite composition `e85b84c31c`,
  the Core build and exact later-cycle owner-association regression pass. Its
  complete no-default-features Core library suite passes all 630 tests with no
  skips, and strict all-target Clippy passes. The owning `core-no-std` Nix gate
  also passes on private `bceb6b16ea`; its actual source matches the complete
  Core directory and both workspace Cargo files byte-for-byte. These results
  qualify that Core source only; native composition and runtime qualification
  remain pending.
  D-115 extends the distinct checkpoint association to final copied first
  ownership and independently qualified optional lineage. Original preparation,
  barrier and valid continuous G/D observations remain fixed while genuinely
  changed current roots use fresh checkpoints. Preparation-initial and ordinary
  sweep associations remain unchanged. On private prerequisite composition
  `f7a9820a31`, the complete no-default-features Core library suite passes all
  631 tests with no skips, and strict all-target Clippy passes. The owning
  `core-no-std` Nix gate also passes; its actual source matches the complete Core
  directory and both workspace Cargo files byte-for-byte. These results qualify
  that Core source only; native composition and runtime qualification remain
  pending.
  The parent-owned native DATA retention prerequisite adds a private observation
  path to the existing neutral restore-pair executor without creator journals or
  a synthetic Trash identity. Ordinary restore and cancellation constructors
  preserve their actual optional journal preimages and refusal rules. A concrete
  owned-source combiner retains executor-produced extraction descriptors beside
  the producer's genuine current check through subsequent effects and waiter
  cancellation, without carrying stale selected cache bodies or granting serving
  permission. These shared prerequisites are source-only; their complete native
  dependencies, compilation and genuine journal-less/restoration fixtures remain
  pending. No task is accepted by introducing them.
  The final copied-owner staging Frames also receive a concrete retained barrier
  combiner. It keeps the actual preparing and NEW-barrier descriptors and
  original elapsed clock observation beside genuine current checks through each
  submitted effect, including disappearance of its waiter. It adds neither a
  caller callback nor a decoded age constructor. Native implementation and real
  cancellation/continuity qualification remain pending.
  The first composed production-only native build on private `7b84c7a7a4`
  fails with thirteen compiler errors: ten aliased child-module paths, one
  private facade import, one slice/vector conversion and one synchronization
  argument order. The disjoint workers have sealed corrections; no native test
  or owning gate passes from this build. Source review also finds ordinary Sweep
  recovery must use its actual registered genesis and authenticated current
  retention traversal, rather than requiring copied visibility at genesis or
  reviving every selected predecessor's expired content (GC-3, GC-4, GC-5,
  GC-15). These ordinary-owner corrections remain unqualified; the distinct
  D-113 copied physical placement path retains its existing obligations.
  Fresh-placement restoration may call the existing whole-observation raw
  proposal validator from the private bucket subtree. Only its Rust visibility
  changes; its complete compare/catalog validation and signature remain fixed.
  The closed restoration producer must still retain genuine current owner,
  lease, Original and source descriptors and consume a real native durability
  acknowledgment. This access change grants no collector or serving permission.
  The next production build on private `6b1c92b383` clears the module-path
  failures and reports eleven actual record-access/ownership errors. The next
  build on `48772a48b6` reports only one wrong merged-row pack field. Both
  terminal failures are retained; genuine native test qualification remains
  pending. Independent restoration review also requires fresh Q payload and
  creation-journal absence even for equal orphan bytes, and finds the tracked
  durability inventory still expected Pending after native Committed replacement.
  The worker seals fresh-only target checks, and the parent corrects the shared
  journal recapture to replace only the matching tracked Pending body with the
  actual native-acknowledged Committed body. Ordinary dedup staging is preserved;
  fresh-placement, collision and durability regressions remain unqualified.
  Private composition `c39bcb8b4c` clears the remaining compiler error and
  passes both default and Tokio production builds. The original terminal logs
  retain twelve unused-item warnings; strict native Clippy and runtime checks
  remain pending. Source review additionally finds ordinary Sweep still loads
  every eligible Live metadata body before its authenticated walker, imposing
  an unrelated availability prerequisite. The worker confines that copied-only
  load to the copied branch. Private `e2302794b9` contains that reviewed fix and
  genuine copied source/destination fixture setup with four uncompiled positive
  cases. The other fifteen copied cases, eleven permanent recovery cases,
  recurring complete passes and the complete local gate set remain pending.
  Production compilation accepts no task and advances no milestone exit.
  On private `e2302794b9`, all ten Scope classification/rebind regressions pass
  in the std Nextest profile, including both actual native rebind cases. The
  207 unselected tests remain outside this result. On later `bd0e671fdb`, strict
  Tokio production Clippy fails with nine diagnostics. Workers correct private
  argument grouping, probe feature scope, flags and copy operations; the parent
  matches the shared Pending unit variant without a struct pattern. Native
  all-target Clippy, collector runtime and index population deadlines remain
  unqualified.
  The shared test binding retains its previously composed native forwarding
  prerequisites and adds typed permanent request gates/faults with separate
  submission and terminal observations. Its retained test task records actual
  worker return even after waiter cancellation; no hook creates a receipt or
  substitutes for a current permission check. Source review and scoped
  formatting pass. Compilation and the five genuine permanent fault witnesses
  remain pending; missing terminal observations cannot prove completion.
  Private `d03e3b3275` passes strict Tokio production-library Clippy after all
  nine corrections. This covers the reviewed Open-event production source;
  the test-only hooks, all-target linting and subsequent recurring-pass changes
  remain outside that result. Five genuine permanent fault cases are drafted
  in a separate worktree, with compilation and runtime still pending.
  Review rejects a recurring-pass prototype whose Discover purpose alone
  claimed complete Trash-family traversal from fixed caller-listed leaves.
  Its replacement uses real native enumeration and retained directory evidence,
  but still imposes a global 4,094-cycle cap. That cap violates D-82's bounded
  event continuation requirement and remains a source correction obligation
  under GC-15, GC-16, GC-24 and GC-29. No pass-completion prototype or fixture
  draft accepts this task or advances the milestone.
  Actual remote provider qualification belongs to T3. No remote conformance
  or full `gc-two-phase-delete` pass is claimed. D-78
  registers physical creation journals and recoverable deletion intent.
  The isolated pre-ownership restore implementation now passes all ten exact
  cases in its owning Nix check on unchanged source. All 4,837 included files
  match the actual derivation. The handoff and reopened-cycle matrices take
  141.25 and 165.56 seconds; their exact Nextest selectors receive exclusive
  slots and a 180-second limit. The metadata-only and fresh-placement cases
  keep their 120-second limit and receive exclusive slots. Production C/G/D/H
  and lease deadlines remain unchanged. A focused native-retirement-faults
  integration check separately requires the six-fixture trash fault matrix;
  its selector is explicitly missing on the current trunk. The unchanged
  isolated matrix passes in its owning Nix check in 134.65 seconds; all 4,840
  included files match that derivation. Its exact Nextest selector receives
  exclusive slots and the same 180-second limit. The existing multiple-source
  disclosure case receives exclusive slots while preserving its 120-second
  test limit and real publication deadline; its isolated pass is recorded
  separately under T-PROV-1. These scheduling changes await native Nextest
  qualification. The isolated local deletion matrix initially runs ten cases
  with one pass and nine failures.
  After correcting retained directory descriptors, genuine full-D ownership,
  actual unlink and synchronization, closed progress acknowledgment and
  idempotent Done pass in the exact positive case in 110.32 seconds. A later
  owning Nix run passes full-D deletion, fresh-placement recovery, recovery at
  each durable prefix under a higher lease epoch, and resynchronization of
  owned absence with idempotent Done. Its fifth fault-matrix case fails the
  final selected-record comparison after genuine bucket reopening refreshes
  the capabilities probe timestamp. The original failure remains preserved;
  a bounded reopen-boundary oracle correction still needs review and execution.
  The remaining five cases do not execute. The original full native suite
  stays red, and no task, milestone or checkbox advances.
  After reviewing that reopen oracle, a subsequent owning run passes the first
  eight deletion cases, including the actual fault prefixes, ownership handoff,
  closed acknowledgment refusals and waiter recovery. The ninth fails on an
  unsupported Note key in its fixture before reconciliation assertions; the
  tenth does not execute. A test-only correction uses the existing supported
  opaque profile Note family in both the publication and exact-record oracle.
  The next unchanged-production run again passes eight cases; its ninth reaches
  actual resumed Done, then fails because the final fixture oracle looks up a
  bare Note name instead of the canonical selected ref-record key. The reviewed
  test-only correction derives that key with `BucketKey::ref_record`.
  The following full ten-case run passes four cases, then refuses during the
  fault matrix's real `mark_batch` lease renewal; the last five do not execute.
  That denial covers several checks and establishes no expiry or load cause.
  Independent frozen-source checks now run those five cases separately. The
  corrected Notes reconciliation case passes in 127.96 seconds; cancellation
  fails in 138.69 seconds at an earlier missing-current-directory-fence refusal,
  before its expected post-durable-Cancelled interruption. The remaining three
  checks subsequently pass: current handoff refusals in 189.46 seconds,
  missing/swallowed acknowledgment refusals in 105.70 seconds, and canceled
  waiter recovery in 117.16 seconds. All five actual inputs match the same
  frozen source. A reviewed correction frames the owned artifacts' actual
  ancestor directories before cancellation, preserving strict fence lookup.
  Its focused run advances beyond the missing-directory refusal, then fails
  final restoration in 181.26 seconds at a fresh collector Session check.
  That diagnostic establishes no expiry, poisoning or scheduling cause.
  Strict default Clippy separately reports two equivalent conditional-style
  corrections; later profiles and rustdoc do not run on that attempt.
  Original failures remain preserved; no full matrix, deletion gate, timing
  fix or task qualification is inferred.
  Subsequent strict default/Send/native Clippy and private rustdoc pass after
  equivalent conditional-style corrections. A bounded test-only Session
  observation identifies the first actual final-check refusal as lease expiry,
  with no prior poison or clock regression; later poison observations follow
  the failed fixture. Original Session bytes are restored after the terminal
  run. The trace does not distinguish cancellation from final restoration
  within that callback. A reviewed local draft separates acknowledged durable
  cancellation, genuine same-holder whole-lease renewal, and complete fresh
  restoration qualification. It discards old successor/read expectations and
  preserves original expiry, validation and durability checks. Native compilation
  and exact-selector discovery pass; the unchanged cancellation witness remains
  pending. No sufficiency or
  deletion-gate success is claimed.
  The unchanged cancellation case on that renewal draft subsequently fails
  with the same `gc-checkpoint` refusal after 196.12 seconds: zero passes,
  one failure, zero ignored. The command stops before any broader matrix or
  quality run. This output does not establish whether cancellation or real
  renewal reached acknowledgment. A finite opt-in test-only phase observation
  now distinguishes those actual boundaries in one private hermetic case;
  source checks and natural restoration timestamps remain explicit. Session,
  timers, assertions and qualification predicates remain unchanged.
  That phase observation reaches durable cancellation, real renewal and fresh
  restore qualification before final restoration refuses without acknowledgment;
  the current refusal predicate remains unknown. A reviewed correction records
  actual completed writes and synchronizes exact restoration outputs, the serving
  maintenance index and all consumed Original controls with unique directories.
  Every retained input and current/pair callback remains checked at each native
  handoff. The unchanged cancellation case now passes with zero ignored in
  183.78 seconds; all 4,848 actual hermetic input files independently match the
  frozen source. Three focused restore regressions also pass with zero ignored:
  actual sync/no-acknowledgment faults, current/pair handoffs and canceled workers.
  The final source differs only by required test-module formatting and passes both
  formatters, strict all-target Clippy and private rustdoc in default, Send and
  native configurations, and application test-target compilation. All 4,848 files
  in that actual quality input independently match the frozen source. The original
  ten-case deletion check now passes all ten exact selectors with zero failures,
  ignored or unrun cases, preserved at `bce511b1392d`. Each original case executes
  one positive test against the same 571-test inventory. Its actual hermetic input
  independently matches all 4,848 frozen files. Nextest qualification remains
  pending: nine measured cases exceed the ordinary 120-second default timeout.
  A shared Nextest override now reserves all test slots for exactly these ten
  cases and bounds each process to 300 seconds, based on measured 100-210-second
  owning runs. No production timer, assertion or qualification window changes.
  The override itself establishes no Nextest pass. Qualified destructive
  source carry, broader collection scenarios and the complete gate remain open.
  Shared private module registrations and a six-case native source-preserving
  retirement prerequisite now reserve complete per-source ordinary visitation,
  genuine loss-generation carry and atomic native acknowledgment before subsequent
  cold reuse. Missing witnesses fail discovery explicitly. Registration grants
  no collection or preservation authority and qualifies no task or gate.
  The reviewed source-retirement candidate `b864eb16dc86`, composed with the
  corrected protected-lineage regression oracle at `e425df68fc06`, now passes
  all six exact native source-preserving retirement cases on its final bytes.
  Actual Node reads, writes and decodes are calibrated after reopening;
  successful cold reuse produces a fresh signed Commit with the expected source
  tree and parent. All 4,904 actual hermetic input files independently match the
  frozen source. Four exact grace-window regressions and the retirement-fault
  case also pass on those same 4,904 independently reviewed input files.
  Required native build and the ten local-deletion Nextest cases remain pending.
  These local prerequisites do not qualify the complete collector gate or close
  T-GC-1.
  Independent review identifies a GC-3/4/5 gap in that source qualifier: its
  unbounded parent cutoff can make unrelated expired ancestral Chunks live.
  It must instead use each source's independently qualified actual current-root
  retention context while retaining full ordinary visitation of the source.
  The cutoff correction and count-zero/duration witnesses remain pending;
  the six-case result alone does not discharge those retention requirements.
  The focused registry now requires eight source cases plus the existing genuine
  live/expired job-root case. The expired lease witness must drop carry rather
  than revive unrelated chunks; count-zero and duration cases require actual
  reclaimability with eligible cold reuse. Missing corrected selectors fail
  explicitly. This registration establishes no corrected runtime result.
  The original composed source subsequently passes native build and all ten
  local-deletion Nextest cases (run
  `90ce17ae-52db-491d-86c1-be04b44564ff`): ten passes, zero ignored or unrun,
  616 outside the exact selection. Independent review verifies all 5,958 frozen
  tracked images including modes and mtimes. Its known retention-cutoff gap
  remains separate from that result. Corrected source `8aab7fbb83f0` passes all
  nine registered preservation cases, including actual count-zero/duration
  reclamation and live/expired job roots. Strict default/Send/native Clippy and
  private docs, application compilation and both formatters also pass; all
  4,898 actual hermetic input files match independent review. The corrected
  source is now normally composed with the reviewed protected-lineage regression
  oracle at `353006757eea`; every cutoff correction is preserved. This corrected
  composition passes all nine exact preservation cases, all four grace-window
  regressions and the actual retirement-fault case. Each selected test passes
  once, with zero ignored and 629 cases outside its scoped run. Strict default,
  Send and native Clippy, private docs, application compilation and both
  mandatory formatters also pass on the unchanged source. Independent review
  verifies all 4,904 actual input files from the five hermetic derivations against
  the 5,958 frozen tracked images, including executable modes; complete tracked
  hashes, modes and mtimes remain unchanged. Corrected composed native build
  and all ten exact local-deletion Nextest cases also pass (run
  `ba2643c2-41ca-403f-a86e-0a232640c0d8`): ten unique passes, zero failed,
  ignored or unrun, and 620 cases outside the exact selection. Independent
  review verifies the original runtime and terminal results, both evidence
  seals and all 5,958 frozen tracked hashes, modes and mtimes. The corrected
  ten-case run takes 1,413.847 seconds with unchanged limits and genuine
  durability, cancellation and recovery assertions. It is separate from the
  historical pre-correction ten-case result. Full collector and current-trunk
  qualification remain pending. T-GC-1 stays open.
  On the same corrected composition, the actual registered
  `gc-roots-complete` gate passes all five exact cases with zero ignored tests;
  `gc-grace-window` succeeds using the same previously qualified four-case
  derivation. Independent review verifies their actual source bindings and
  unchanged complete tracked snapshot. Its subsequent aggregate exits 1 at
  the explicit pending `algebra-fork` dependency (ALG-32); pending physical
  deletion and index-maintenance dependencies are also reported. This bounded
  root/grace qualification does not complete the collector or T1.
  A focused integration check now requires genuine retirement carrying a local
  head's foreign used views, followed by a zero-TreeNode fork of that same head.
  Its named selector must execute and pass without ignored tests. Missing
  inventory fails explicitly; registration establishes no runtime result.
  Its first runtime stops at unavailable filesystem xattr reads in the native
  test wrapper. After delegating those reads to the actual filesystem, genuine
  imported publication and retirement execute, but the witness incorrectly
  requires the seeded orphan to be the first eligible catalog pack. That exact
  case fails with zero passes in 233.74 seconds, before the cold fork. A reviewed
  fixture correction bounds distinct native-acknowledged retirements by the
  actual inventory, preserves every per-step source/control invariant, and
  still requires the exact seeded orphan and final loss count. Corrected
  execution remains pending; both original failures and dependent unrun checks
  remain recorded. Neither result qualifies imported-head cold reuse.
  The corrected composition `9d5cd28c33ae` subsequently passes the exact
  imported-source owning case, all nine source-carry and thirteen cold-fork
  regressions, strict three-profile Clippy/private docs, application compilation
  and both formatters. Independent review binds all five actual derivations
  and the unchanged full tracked source. The complete native collector and
  current trunk remain unqualified; T-GC-1 stays open.
  The reviewed pure journal, marking, proof-context, checkpoint, retention and
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
  The shared native creation executor retains original Pending, artifact and
  protected-control descriptors and exclusions through worker completion. Its
  result channels are private and filled only after the corresponding actual
  durability boundary. Closed-result refusal, compilation, rustdoc and existing
  backend checks pass as recorded in T1's status; actual pack/index producer
  adoption and positive creation-journal qualification remain pending.
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
  The trunk held-lease context now retains the actual namespace and Original
  exclusions across whole-lease renewal. Shared durability work synchronizes
  exact completed outputs and all required Original records while retaining
  complete historical preimage checks. The final closed acknowledgment keeps
  its real missing-result diagnostic without changing the Unsupported outcome.
  All six held-context and five output-sync cases pass on the corrected trunk
  source, as does `checks.terrane.integration.native-lease-output-sync`.
  The preceding composition also passes the held-six, mutation-twelve and
  singleton-nineteen Nix checks, plus the 41 selected native runtime cases
  except the subsequently corrected missing-diagnostic assertion. Default and
  Send compilation, strict private rustdoc and both formatters pass. Strict
  SDK Clippy remains red on unfinished integration paths. The isolated retained
  Original-history composition now passes all six actual local first-ownership
  cases in `checks.terrane.integration.native-local-first-ownership`, including
  full-D waiting, exact partial fault prefixes, genuine renewal-I/O refusal and
  current checks at every ownership effect. Its scoped stopped-Session correction
  separately passes all three original refusal assertions and eleven held/output
  regressions. Restored temporary timing traces show 55–67 seconds of fixture
  preparation before the required real 60-second D wait; the ordinary 120-second
  Nextest limit could therefore expire before the assertions. The trunk test
  configuration reserves test slots and permits a bounded 180 seconds only for
  the two parallel ownership matrices. Production timing, waits and assertions
  remain unchanged. Separate uninstrumented Nextest runs pass the original
  current-authority case in 133 seconds and the five-fault case in 110 seconds;
  both formatting commands pass. These results qualify the isolated prerequisite
  source, not the full trunk collector gate. Actual unlink/recovery and the
  excluded-but-still-Live fresh-admission branch remain unqualified, and this
  task and T1 remain open.
  The same checkpointed isolated source separately passes the original genuine
  retirement/readmission/exact-restore Nextest case. It exercises the actual
  collector producer and does not cover the mixed-live fresh-admission gap.
  The focused `checks.terrane.integration.native-local-deletion` check is
  registered before implementation. Its ten exact cases require genuine
  ordinary local-v1 unlink, directory synchronization, protected progress,
  fresh-collector recovery, current reconciliation and durable restore
  cancellation. The existing first-ownership result ends at Invalidated and
  cannot substitute for these cases. Remote-v2 permanent ownership remains
  separate. Missing selectors fail explicitly; the full two-phase gate stays
  pending until its actual requirements and runtime inventory are qualified.
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
  A focused `checks.terrane.integration.native-recorded-disclosure` check is
  registered before its isolated native implementation. Its four exact cases
  require genuine earlier certificate publication followed by completed
  Recorded history, exact original-root associations, complete dependencies,
  independent current fences and retained Original roles. Missing selectors
  fail explicitly. The isolated implementation now passes those four exact
  owning Nix cases and ten focused native cases on unchanged source, including
  six existing completed-view regressions. Every one of the 4,837 included
  source files matches the actual owning derivation. Native, default and Send
  strict all-target Clippy and private rustdoc pass, as do the default build,
  all 156 default-profile tests, application test-target compilation and both
  mandatory formatters. Full native Nextest remains red: 570 run, 564 passed,
  one expired publication failure and five existing restore/retirement cases
  timed out at 120 seconds, with none skipped. The unchanged multiple-source
  disclosure case separately passes alone in 36.095 seconds; this diagnostic
  does not replace the failed full run or establish a causal explanation.
  Original failures and production deadlines remain unchanged. These results
  qualify only the isolated source; no task merge or checkbox advances. Fresh
  Recorded candidate admission and required index completion are separate.
  A new complete native run with the reviewed measured scheduling changes
  executes all 570 discovered cases: 569 pass, one publication expires and none
  time out or skip. UUID `8e9bfc85-70b3-4373-857e-f1871fb9a236` takes
  2,710.534 seconds on unchanged `a1ef041c2d6f`; all 4,840 source/configuration
  guards match. The failed case is
  `disclosure_projection_safe_index_rebuild_requires_current_attribute_producers`,
  whose narrowed publication returns `Advance(Expired)` before its final
  forbidden-producer read. The original full failure remains unqualified.
  That unchanged case separately passes alone with existing phase tracing:
  UUID `84cff25d-0c5d-45cf-871d-84de56302742`, 96.625 seconds, one pass and
  569 deliberately filtered cases. Its narrowed publication dispatches at
  20.238 seconds and reaches durable acknowledgment at 25.878 seconds from
  the actual request origin, within unchanged C30. No corresponding trace
  exists for the full-run failure, so this diagnostic establishes no cause
  or timing fix and replaces neither failed full result.
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
  Reviewed private `0a08ab5811` adopts the existing local frontend and public
  SDK witnesses onto the current trunk base in exactly eight owned files.
  Every adopted byte matches `066d12c9f5`; Cargo dependencies, shared library
  files, assertions and deadlines remain unchanged. The five local commands
  call ordinary repository factories and verbs, and checkout uses registered
  `realize` with pinned SDK presentation. Independent review reads the entire
  eight-file diff and verifies all 5,682 tracked contents, Git blobs, modes and
  symlink targets. The exact mandatory formatter pair passes without source
  changes. Compiler and runtime checks remain unrun, and the newer shared
  runtime must be composed and reviewed before qualification. Required evidence
  remains the current feature matrix, five-case local SDK prerequisite,
  three-case separate-process CLI prerequisite, required package tests and
  genuine ext4 guest workflow; older candidate passes do not qualify this source.
  Independent comparison also finds all eight files already present byte-for-byte
  in the current native `201f568606` candidate. Its owning SDK and CLI prerequisites
  can therefore run on that frozen runtime after native qualification without
  another frontend copy. This equality is source evidence, not an execution result.
  Current frozen `c99810493f` now passes all three owning local prerequisites:
  `local-factory-construction` (two cases), `local-sdk-checkout` (five cases),
  and `local-cli-workflow` (three cases). All ten cases execute with zero ignored
  tests in fresh hermetic builds. The separate-process CLI workflow completes
  initialization, commits, fork, merge, registered merged checkout and fixed
  historical checkout in 79.11 seconds under the unchanged 120-second limit.
  The complete tracked source remains unchanged, and the actual builder source
  matches the frozen commit. These checks qualify the local prerequisites;
  feature-matrix, package, ext4 and full trunk qualification remain pending.
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
