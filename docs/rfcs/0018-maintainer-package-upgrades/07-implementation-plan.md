# Implementation plan

## Delivery principles

- Land the data contract and read-only evidence before any automatic write.
- Separate metadata migration from package version updates so review can prove
  no source/build identity changed.
- Prove one local command at a time; no background execution is required.
- Do not execute candidate evaluation, materialization, builds, tests, or agent
  tools outside a verified local confinement boundary, including during the
  early vertical slice.
- Start with conventional low-risk units and retain manual handling for complex
  packages until their typed adapter exists.
- Make every schema closed, versioned, bounded, canonical, and fixture-tested.
- Keep the pure policy/state core separate from filesystem/network/Nix/Git/model
  effects.
- Do not weaken AOS hermeticity or import nixpkgs while adding the tool.
- Treat agent repair and PR publication as final layers over a complete
  deterministic workflow.
- Treat presentation as a versioned product contract. Every implementation PR
  that adds a state, event, action, or disposition updates rich/plain/machine
  fixtures and exact next-action output in the same change.

## PR 1: Shared contracts and thin maintenance model

Extract RFC-0017's canonical JSON, digest, bounded-decoding, and primitive
contract support into one pure crate such as `aos-contract`, preserving all
existing `aos-release` byte fixtures. Add a thin `aos-maintain` crate with:

- inventory envelope, component observation/candidate vector, campaign plan,
  gate plan, run, attempt, mutation, and evidence v1 schemas;
- unit, family/stream, member, component, source/artifact, cohort, campaign,
  classification, and lifecycle identities;
- legal state transitions and invalidation rules;
- typed stream selectors, candidate/package-version projections, source
  assurance outcomes, and risk interfaces;
- separate durable journal and transient progress events, command results,
  dispositions, diagnostics, next actions, and pure presentation views;
- hostile, boundary, compatibility, and transition fixtures.

Both crates perform no I/O and meet the repository Rust documentation standard.

**Exit:** release canonical/digest fixtures are unchanged; update schemas reject
malformed/oversized/unknown input; fixtures cover single/multi-component,
single/multi-unit campaign, concurrent-major, generated-output, frozen, alias,
and exceptional cases.

## PR 2: Minimal Nix contract and inventory envelope

Add the smallest vertical package contract for one conventional canary:

- `mkUpstream` with one component/source slot and package-version projection;
- `update ? null` handling in AOS-local `mkDerivation`;
- normalized `passthru.aos.maintenance`;
- pure Nix content inventory with no Git claim;
- a Rust repository envelope binding canonical remote, local clone/common-dir,
  clean commit/tree or dirty content digest, target, inventory digest, and
  frozen controller identity;
- one package-constructor fixture and report-only coverage check.

Do not change the canary package version/URL/hash in committed source.

**Exit:** Rust consumes the content inventory/envelope; dirty bytes cannot be
reported as `HEAD` or used for a write plan; metadata does not enter the builder
environment; the existing package derivation identity remains explainable.

## PR 3: Early end-to-end conventional vertical slice

Before generalizing the schemas, prove one complete local update path:

- one direct primary adapter with coverage-through-current proof;
- minimal repository-bound XDG inventory/observation cache, state permissions,
  and single-provider request lease/budget primitives that later PRs generalize;
- one component version-range selector and candidate projection;
- bounded trusted source fetch, origin-integrity result, and source hash;
- one comment-preserving literal expected-value edit;
- a minimal campaign plan, local lock/journal, worktree, and reconstructible
  attempt patch/manifest;
- a minimal Linux confinement implementation satisfying the filesystem,
  process, network, credential, resource, and complete-worker-reaping contract
  for this canary path;
- formatting, evaluation, one package build/check, semantic/derived delta, and
  interruption/resume;
- canary-scoped `scan` and `report`, then `plan`,
  `run --until quick-gated`, `status`, `inspect`, and `diff`;
- responsive rich-inline, plain, screen-reader, one-document JSON, and JSONL
  views for those commands, with stable stdout/stderr and exit contracts;
- centralized injectable terminal capabilities, graceful Ctrl-C checkpointing,
  one final result, and exact resume/inspection commands;
- a non-exiting recognized-maintenance parse/dispatch path and typed
  `CommandCompletion`; maintenance code emits no incremental `Printer` JSON;
- one real package-update rehearsal in an unpublished disposable worktree,
  captured in the PR evidence but not committed as a package bump.

No agent, generated dependency, remote Git, or broad package migration is
included.

**Exit:** a maintainer can reproduce one real conventional update from
observation to tested worktree; kill/restart tests resume or stop at verified
boundaries; basic hostile filesystem/network/process fixtures pass; observed
constraints feed back into the v1 contract before it spreads across the tree;
the M0 usability exercise in the interface chapter passes without consulting
raw implementation logs.

## PR 4: Root universe, fixed-output instrumentation, and classification

Reconcile every supported target's package discovery, lint, build, and release
root sets into one explicit maintenance-root universe. Add metadata paths for
local/generated/alias/frozen and stdenv/package-set roots.

Instrument every AOS source/fixed-output constructor with typed identity and
builder parameters. Add derivation-input-graph auditing that maps all reachable
fixed-output derivations to declared slots or explicit manual exceptions.

Then census and classify:

- package roots/aliases, literal/revision versions, shared/duplicate sources;
- Cargo, Go, npm, Bazel, nested, target-conditioned, and embedded phase inputs;
- package checks, targets, dependencies, and reverse dependencies;
- concurrent major/LTS/compiler streams and existing shared `_source.nix` units.

Metadata conversion does not update package versions or inputs.

**Exit:** all root-set count differences are explained; every package is
classified; every schedulable member has a unit; every reachable fixed-output
input is declared or explicitly manual; reports contain no guessed mapping.

## PR 5: Full inventory checks, discovery, and reporting

Promote coverage/uniqueness/owner/slot/artifact/member/alias/freeze/target/cohort
findings into fail-closed checks. Implement:

- XDG state/cache permissions and bounded content storage;
- host-wide provider request lease/budget state;
- direct provider interface with completeness/truncation proof;
- initial adapters selected from the inventory;
- Repology pacing, `Retry-After`, compliant user agent, raw records, explicit
  mapping, and unknown/disagreement behavior;
- typed version-range/channel/VCS-lineage selectors;
- projection-collision quarantine, observation freshness, stabilization basis,
  and immutable discovery snapshots;
- `inventory`, `scan`, `scan --offline`, and `report` commands;
- adaptive inbox, family, unknown, and quarantine reports at the specified
  terminal widths, with semantic JSON assertions and CLI golden fixtures.

This PR remains read-only with respect to repository source and Git. It
generalizes and hardens the minimal XDG cache/lease primitives proven in PR 3
rather than introducing an incompatible second storage path.

**Exit:** a repository-wide scan is reproducible; truncated provider windows
cannot yield `no-change`; concurrent majors report per stream; unavailable or
ambiguous evidence is unknown/quarantined.

## PR 6: General campaigns, worktrees, and semantic editing

Generalize the PR 3 slice to:

- multi-component target vectors and package-version projections;
- one-unit campaigns plus explicit multi-unit cohort/dependency campaigns;
- repository/clone-bound state, durable journal writes, recovery, and retained
  attempt patches/manifests;
- `dplecki/upgrade-*` branches and safe human-work adoption/cleanup;
- exact authored-field/generated-output CAS plus typed derived-effect closure;
- URL-template AST/contextual encoding;
- full path/file/mode/symlink/submodule/binary/size diff policy;
- `plan`, `run --until worktree-ready`, `status`, `inspect`, `diff`, `resume`,
  `abandon`, and `clean`.

Add the optional read-only `aos maintain ui [RUN]` cockpit only after command,
plain, and JSON parity is complete. If included here, it reuses the workspace
Ratatui/Crossterm versions, the same pure views, and a tested terminal guard;
no state transition exists only in the cockpit.

No agent, networked generated materializer, or remote Git operation is included.

**Exit:** multi-component/cohort fixtures close complete vectors in one
campaign; ambiguity has no regex fallback; human work is preserved; independent
clones cannot collide; attempts remain reconstructible after later edits.

## PR 7: Local confinement and restricted candidate evaluation

Productionize the mandatory confinement backend proven narrowly in PR 3 before
enabling additional package or materializer kinds:

- Linux subordinate UID, private user/mount/PID/IPC/UTS/network namespaces,
  minimal mounts/private proc, syscall/device policy, cgroup limits, complete
  worker-tree reaping, and externally enforced egress;
- Darwin disposable local-VM implementation with the same contract;
- private Nix evaluation/build context rather than arbitrary host-daemon access;
- empty-environment pure/restricted Nix evaluation, allowed imports, IFD off,
  network off, and explicit target/system;
- KVM capability passthrough only for planned tests;
- teardown proof before commit/signing/publication phases;
- negative filesystem, `/proc`, socket, signal, credential, evaluation-fetch,
  IFD, network, persistence, and orphan-process tests.

**Exit:** candidate evaluation/tests and agent tools fail closed on a host
without a verified backend; hostile fixtures cannot reach undeclared host state,
network, Git, credentials, or later privileged phases.

## PR 8 series: Typed source and artifact materializers

Refactor [`aos prefetch`](../../../crates/aos/src/commands/prefetch.rs) transfer
and hash machinery, then add materializer kinds incrementally:

1. flat/recursive source slots;
2. Cargo dependency/vendor inputs;
3. one or several Go module inputs;
4. npm inputs and declared lock/manifest transformations;
5. Bazel dependency inputs;
6. target-conditioned source/artifact slots.

Each kind lands only with its closed builder-parameter and repository-output
contracts, confinement/egress/script policy, deterministic/failure fixtures,
and an end-to-end writing pilot for a representative real unit. Unpiloted kinds
remain manual and outside M2 claims.

Deprecate `aos prefetch --update` as each supported kind moves to semantic CAS;
retain useful read-only hashing.

**Exit:** every enabled kind atomically updates all declared inputs, executes no
undeclared lifecycle logic, writes no undeclared/preimage-mismatched file, and
preserves a network-disabled final package build.

## PR 9: Affected graph, final validation, and deterministic pilot

Add evaluated package/check/reverse-dependency graph extraction, quick canary
and complete final gate planning, all-target behavior, exceptional gates,
exact-commit invalidation/evidence, and `test`, `accept`, `commit`, and
`evidence` commands. Freeze the base controller; candidate `pkgs.aos` is tested
as an artifact, never made the run authority.

Pilot approximately 15–25 low/normal-risk units with agent disabled. Include
each enabled materializer kind plus non-writing schema/gate exercises for shared
Linux source, concurrent Bazel majors, a composite component vector, a frozen
bootstrap rung, and exceptional QEMU/Crucible.

**Exit:** conventional/enabled generated-input updates reach `ready-for-pr` only
after the exact candidate commit passes all local gates; unavailable target/KVM
capability is visible; no pilot uses manual text replacement; dossiers capture
review corrections and resource cost.

## PR 10: Bounded agent repair

Implement the trusted provider-neutral model client, closed task/results,
confined disposable source views, typed tools, inference/tool credential
separation, patch gateway, scope requests, maintainer acceptance, and budgets.

Changes beyond declarative update fields and typed generated outputs—patches,
phases, flags, dependencies, hardening, tests, or licenses—always block for a
new maintainer-approved plan even when the agent proposes them. `--agent none`
remains supported.

Render repair as controller-owned stages and an action-required card. Model
prose and model-reported task lists remain bounded logs, never the progress or
completion authority. Scope expansion shows the semantic delta, invalidated
evidence, new plan digest, and exact acceptance action.

**Exit:** representative repairs work; injection cannot reach secrets/Git/policy;
the agent cannot autonomously accept semantic-risk changes, expand scope, or
mark validation successful; the worker tree is dead before commit credentials
are available.

## PR 11: Git and pull-request handoff

Implement offline `prepare-pr`, sanitized hook-free commit/push configuration,
author/signature/attribution/base/head validation, exact refspec and expected
remote head, explicit confirmation, authentication isolation, create/update-
only matching PR behavior, and partial-failure reconciliation.

Implement explicit `observe-pr` with a separately selected least-privilege read
credential. `status` and `inspect` remain local/cached and never acquire remote
authentication or perform an implicit refresh.

Add exact-head commit and publication previews that leave any alternate screen,
name remote effects, irreversibility, and recovery, bind confirmation to all
displayed digests, and reject non-interactive ambiguity. There is no broad
`--yes` path.

Local preflight records contributor authorization as `pending-remote`. A later
explicit `observe-pr RUN` may record the repository's exact-head authorization,
review, and check results as `merge-eligible-observed`.

**Exit:** a maintainer can publish a final-gated branch/PR explicitly; untrusted
children and hooks never receive credentials; failure preserves local state;
the command has no force-push/tag/merge/release/package-publication path;
`observe-pr` can refresh exact-head remote evidence without gaining a write
capability, while ordinary status/inspection remains local.

## PR 12: Complex expansion and RFC-0017 identity handoff

Expand typed support for shared sources, lifecycle/default aliases, larger
artifact graphs/patch stacks, compiler cohorts, curated component vectors, and
human-led exceptional campaigns. Add the resolved unit/family/stream/component/
source identity subset to RFC-0017 release inventory without maintainer mutation
or agent state.

**Exit:** a protected merged commit can be traced to its upstream unit/component
identity while RFC-0017 independently evaluates, rebuilds, tests, and publishes
it.

## Milestones

### M0: Early vertical proof

PRs 1–3. The shared contract, smallest package metadata shape, repository
envelope, and one real conventional update are proven end to end before the
design is generalized.

### M1: Complete observability

PRs 4–5. Every maintenance root and reachable fixed-output input is classified;
maintainers can obtain an evidence-backed staleness report without source
mutation.

### M2: Deterministic local campaigns

PRs 6–9. Conventional units and explicit cohorts can be updated, hashed, tested,
inspected, resumed, and prepared for review entirely through local commands and
the mandatory confinement backend.

### M3: Assisted local updates

PR 10. Bounded agent repair handles selected contextual failures while the
deterministic path remains authoritative.

### M4: Maintainer-owned PR handoff

PR 11. The final branch and PR are published explicitly through the
maintainer's identity.

### M5: Broader package coverage

PR 12 and later. Add complex typed archetypes only when fixtures and gates make
their automation at least as safe and understandable as manual maintenance.

## Acceptance matrix

| Capability | Required proof |
| --- | --- |
| Inventory | Reconciled root universe; complete classification; all reachable fixed-output inputs declared; closed canonical Nix/Rust round-trip |
| Provenance | Pure content inventory wrapped by an exact remote/clone/commit-or-dirty-content/controller envelope |
| Components | Complete compatible component vector and deterministic package-version projection |
| Campaigns | All units in an explicit cohort/dependency transaction close in one worktree, journal, gate set, and PR |
| Concurrent majors | Independent per-stream selection and lifecycle; no sibling mutation |
| Provider discovery | Coverage-through-current or stream-bound proof; truncation and ambiguity cannot report `no-change` |
| Shared source | All members update atomically and agree on identity |
| Semantic writer | Exact authored CAS plus allowed derived-effect closure; comments preserved; ambiguity rejected |
| Source handling | Origin, redirect, digest, and assurance outcome recorded; same-ID change quarantined |
| Artifact handling | Ordered complete hash/output regeneration with typed preimages and transformations; hermetic final build |
| Worktrees | Human changes preserved; safe resume/adopt/cleanup; retained attempts are reconstructible |
| Confinement | Candidate evaluation and execution cannot reach undeclared host state, network, credentials, or later privileged phases |
| Agent | Typed bounded tools; no secret/Git/policy authority; semantic-risk changes require a new human plan |
| Validation | Quick affected feedback plus all final exact-head tests under the frozen base controller |
| Host limitations | Missing confinement, target, KVM, or test capability remains action-required |
| Evidence | Complete bounded dossier, corruption-detecting journal, sanitized PR rendering, release boundary explicit |
| Publication | Hook-free one-shot publisher; explicit maintainer confirmation; exact refspec/expected head; no force/merge/release |
| Remote observation | Explicit `observe-pr`; least-privilege read credential; exact-head provenance; no mutation; local status never refreshes implicitly |
| Legal | Local preflight distinguishes identity/signature from remote authorization; authorization remains fail-closed; QEMU DCO is never synthesized |
| Maintainer UX | Rich inline, plain, screen-reader, JSON, and JSONL views reduce the same typed state; responsive/golden/interrupt/prompt tests pass; every pause has an exact next action; full-screen UI is optional |

## Migration completion criteria

Write mode remains opt-in until:

- the early vertical slice has completed a real disposable-worktree rehearsal;
- every supported target root is reconciled into the maintenance universe and
  every package has a valid classification;
- automatic/assisted owner paths and fields are literal and unique;
- every reachable fixed-output derivation is represented by a declared slot or
  explicit manual exception;
- all maintained concurrent streams and component vectors have independent,
  complete policy;
- frozen units have owners and non-expired review dates;
- direct providers prove observation completeness, Repology mappings are
  reviewed, and truncation/collision fixtures pass;
- the local journal/worktree recovery suite passes failure injection;
- the semantic writer has no heuristic fallback;
- mandatory confinement and restricted candidate evaluation pass their hostile
  fixtures;
- every enabled materializer has a real writing pilot and preserves hermetic
  final builds;
- a deterministic pilot demonstrates complete evidence and acceptable review
  quality.

Agent-assisted write mode has its own later enablement gate. Git/PR publication
is later still and never becomes implicit in `run`.

## Rollback and compatibility

Package metadata schemas are versioned. The inventory reader supports only
explicit compatible versions and fails on unknown semantics. A helper change
that alters normalized inventory data requires fixture updates and an inventory
schema decision.

The package build remains usable if maintainer tooling is not invoked. If the
tool must be rolled back, update metadata remains pure inert evaluation data and
maintainers can edit packages normally. Do not retain dual regex/semantic write
paths: once a hash kind moves to the semantic writer, rollback means using an
older read-only tool plus manual editing, not re-enabling unsafe mutation.

Local run/evidence formats preserve their schema identifier and migration tool.
An older tool refuses a newer state directory rather than partially interpreting
it. Cleanup/export remains available through the version that created the run.
The repository envelope also records the frozen controller identity; resume
requires that controller or an explicitly compatible migration implementation.
