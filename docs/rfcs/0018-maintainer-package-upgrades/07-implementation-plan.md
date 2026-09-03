# Implementation plan

## Delivery principles

- Land the data contract and read-only evidence before any automatic write.
- Separate metadata migration from package version updates so review can prove
  no source/build identity changed.
- Prove one local command at a time; no background execution is required.
- Start with conventional low-risk units and retain manual handling for complex
  packages until their typed adapter exists.
- Make every schema closed, versioned, bounded, canonical, and fixture-tested.
- Keep the pure policy/state core separate from filesystem/network/Nix/Git/model
  effects.
- Do not weaken AOS hermeticity or import nixpkgs while adding the tool.
- Treat agent repair and PR publication as final layers over a complete
  deterministic workflow.

## PR 1: Pure maintenance model

Add the `aos-maintain` library crate with:

- inventory, upstream observation, candidate, plan, gate plan, run, attempt,
  mutation, and evidence v1 schemas;
- canonical JSON encoding and digest rules;
- size/count/string/depth limits and unknown-field rejection;
- update-unit, family/stream, member, component, source/artifact, and cohort
  identities;
- classifications and lifecycle states;
- legal state transitions and invalidation rules;
- version-policy and risk interfaces with fixture implementations;
- hostile, boundary, canonicalization, compatibility, and transition tests.

The crate performs no I/O. Add crate/module/public-item rustdoc to the repository
standard.

**Exit:** all schemas round-trip canonically, malformed/oversized/unknown input
fails closed, illegal transitions are unrepresentable or rejected, and fixtures
cover conventional, shared, concurrent-major, generated-input, frozen, alias,
and exceptional units.

## PR 2: Nix contract and inventory prototype

Add:

- `mkUpstream` and source-slot construction;
- `update ? null` handling in AOS-local `mkDerivation`;
- forwarding through each higher-level package constructor;
- normalized `passthru.aos.maintenance` data;
- pure maintenance inventory extraction and canonical JSON output;
- evaluation fixtures for every package constructor and archetype;
- report-only coverage checks.

Convert a small fixture/canary set without changing any package version, URL,
hash, dependency, phase, or output.

**Exit:** the Rust model consumes the Nix inventory; update metadata does not
reach builder environments or change package derivation identity except where
source construction is deliberately normalized; missing forwarding is detected
by fixtures.

## PR 3: Repository census and classification

Create a read-only census of:

- evaluated package attributes and aliases;
- top-level and nested source derivations;
- literal versions and revision-like identities;
- Cargo, Go, npm, Bazel, and other fixed-output builders;
- shared/duplicate URL+hash identities;
- package-authored checks;
- target support;
- dependencies and reverse dependencies;
- existing shared `_source.nix` ownership.

Classify every package as automatic, assisted, manual, frozen, local, generated,
or alias. Add family/stream identities for concurrent major versions and
compiler ladders. Consolidate duplicated shared sources only where ownership is
unambiguous.

Metadata conversion does not upgrade packages. Large categories can be split
into several reviewable commits/PRs, but the final census has one completeness
report.

**Exit:** every evaluated package is classified; every schedulable member has a
unit; every fixed-output input is represented or carries an explicit manual
exception; reports contain no guessed upstream mapping.

## PR 4: Fail-closed inventory checks

Promote report findings into evaluation checks for:

- coverage, uniqueness, owner paths, literal automatic fields;
- version stream/policy validity;
- source/artifact references and DAGs;
- shared-member agreement;
- alias/generated ownership;
- manual/frozen reasons and review dates;
- target/check/cohort/exceptional-gate references;
- canonical Rust round-trip fixtures.

Add `aos maintain inventory [--check] [--json]` and human coverage rendering.

**Exit:** a newly auto-discovered package cannot land without an explicit valid
classification; contradictory metadata fails during normal evaluation.

## PR 5: Local discovery and reporting

Implement:

- XDG state/cache resolution and restrictive permissions;
- bounded content-addressed response storage and mutable cache projections;
- direct provider adapter interface;
- initial adapters selected by inventory coverage;
- Repology mapping, global one-request-per-second pacing, compliant user agent,
  raw-record preservation, and typed unknown/disagreement handling;
- version normalization and maintained-stream selection;
- immutable discovery snapshots;
- `scan`, `scan --offline`, and `report` commands;
- provider/cache corruption, pagination, rate-limit, freshness, and ambiguity
  fixtures.

This PR is read-only with respect to repository source and Git.

**Exit:** a repository-wide scan is reproducible from its snapshot/cache,
concurrent majors are reported per stream, and every unavailable/ambiguous
source is unknown or quarantined rather than incorrectly current.

## PR 6: Plans, worktrees, and semantic editing

Implement:

- closed update plans bound to base/inventory/snapshot/current identity;
- local repository/run locks, journal intents, and recovery;
- isolated Git worktree creation under the selected state root;
- `dplecki/upgrade-*` branch naming and collision handling;
- comment-preserving Nix syntax-tree parsing;
- unit/owner/field/expected-value compare-and-swap mutation;
- before/after inventory semantic-delta proof;
- filesystem diff policy and safe worktree adoption/cleanup;
- `plan`, `run --until materialized`, `status`, `inspect`, `diff`, `resume`,
  `abandon`, and `clean` commands.

No agent or remote Git operation is included.

**Exit:** fixture updates preserve comments and unrelated formatting, ambiguous
or dynamic values fail without regex fallback, human work is never overwritten,
and kill/restart tests resume or stop at verified journal boundaries.

## PR 7: Source and fixed-output materialization

Refactor the transfer/hash machinery behind
[`aos prefetch`](../../../crates/aos/src/commands/prefetch.rs) into reusable AOS
components, then implement typed materialization for:

1. flat/recursive source slots;
2. Cargo dependency/vendor inputs;
3. one or several Go module inputs;
4. npm inputs and reviewed lock/manifest transformations;
5. Bazel dependency inputs;
6. target-conditioned source/artifact slots.

Each materializer has a closed config/result schema, origin/network limits,
dependency ordering, deterministic output, expected-value mutation, and
failure-injection tests. Package builds remain network-disabled.

Deprecate `aos prefetch --update` after every supported hash update routes
through the semantic writer. Keep a read-only prefetch/hash interface where
useful.

**Exit:** supported units update every declared source/artifact atomically; an
unknown artifact kind cannot run arbitrary code; repeated materialization from
the same inputs yields the same recorded identity.

## PR 8: Affected graph and complete local validation

Add:

- evaluated package/check/reverse-dependency graph extraction;
- quick canary and complete final gate planners;
- integration with `aos fmt --check`, `aos lint`, `checks.eval`, package builds,
  package-authored checks, and every `aos test` layer;
- all-target handling through the configured AOS build environment;
- exceptional bootstrap/kernel/init/crypto/Secure Boot/QEMU/Crucible gates;
- exact tree/commit invalidation and result evidence;
- unavailable-capability/action-required behavior;
- `test --quick`, `test --final`, `accept`, `commit`, and `evidence` commands.

**Exit:** a conventional update reaches `ready-for-pr` only after the exact
candidate commit passes all required local gates; edits/rebases invalidate the
correct results; an unavailable target or KVM capability cannot be hidden.

## PR 9: Deterministic pilot

Select approximately 15–25 low/normal-risk conventional source units using the
inventory, with these criteria:

- literal `mkUpstream` fields;
- one stable maintained stream;
- no bootstrap, init, kernel, crypto-root, Secure Boot, QEMU/Crucible, or
  publication role;
- modest reverse-dependency closure;
- package-authored check where practical;
- direct upstream adapter and unambiguous Repology mapping;
- no unresolved license, signature, mirror, or generated-input concern.

Run the complete local workflow with agent disabled. Maintainers publish PRs
manually from the resulting branches while measuring discovery accuracy,
semantic edit reliability, materialization success, quick/final gate cost, and
review corrections.

Include non-writing schema/gate exercises for:

- the Linux shared source;
- concurrent Bazel majors;
- a Cargo input;
- a package with several Go modules;
- a platform-conditioned input;
- a frozen bootstrap rung;
- an exceptional QEMU/Crucible unit.

**Exit:** no pilot uses manual text replacement; every accepted update has a
complete reproducible dossier; observed design gaps are fixed before agent
write capability is introduced.

## PR 10: Bounded agent repair

Implement:

- provider-neutral model adapter in the trusted local parent;
- closed agent task/result schemas;
- bounded disposable source views;
- typed read/search/patch/test-request capabilities;
- inference/tool credential separation;
- patch gateway, scope requests, maintainer acceptance, and attempt budgets;
- `repair` and `run --agent PROFILE`;
- injection, secret, path, Git, policy, budget, and forbidden-repair tests.

Enable only selected low/normal-risk assisted units first. `--agent none`
remains fully supported.

**Exit:** an agent can repair a representative patch/build failure, but cannot
read unrelated files/credentials, change Git, expand scope, weaken a feature or
test, alter policy, or mark validation successful.

## PR 11: Git and pull-request handoff

Implement:

- offline `prepare-pr` rendering;
- commit author/signature/attribution/base/head validation;
- expected-remote-head branch push;
- explicit confirmation and authentication isolation;
- create/update-only matching PR behavior;
- retry/reconciliation after partial remote failure;
- PR evidence summary and reproduction commands;
- strict prohibition of force push, tag, merge, release, package publication,
  or RFC-0017 command paths.

**Exit:** a maintainer can publish a final-gated branch/PR from one explicit
command; credentials appear only in that command's trusted transport; failure
leaves the local branch intact; the tool cannot merge or release.

## PR 12: Complex unit expansion and RFC-0017 identity handoff

Expand typed support deliberately:

- shared-source families and duplicated-source consolidation;
- concurrent-major lifecycle/default-alias reports;
- larger generated-input graphs and patch stacks;
- compiler/toolchain cohorts;
- curated multi-component units;
- human-led exceptional flows.

Add the resolved update-unit/family/stream/source identity subset to the
RFC-0017 release inventory. Do not add maintainer mutation or agent state to the
release schema.

**Exit:** a protected merged commit can be traced to its upstream update-unit
identity, while the release planner independently evaluates, rebuilds, tests,
and publishes it.

## Milestones

### M0: Complete observability

PRs 1–5. Every package is classified; maintainers can obtain an evidence-backed
staleness report without source mutation.

### M1: Deterministic local updates

PRs 6–9. Conventional units can be updated, hashed, tested, inspected, resumed,
and prepared for review entirely through local commands.

### M2: Assisted local updates

PR 10. Bounded agent repair handles selected contextual failures while the
deterministic path remains authoritative.

### M3: Maintainer-owned PR handoff

PR 11. The final branch and PR are published explicitly through the
maintainer's identity.

### M4: Broader package coverage

PR 12 and later. Add complex typed archetypes only when fixtures and gates make
their automation at least as safe and understandable as manual maintenance.

## Acceptance matrix

| Capability | Required proof |
| --- | --- |
| Inventory | Complete package classification; closed canonical Rust/Nix round-trip |
| Concurrent majors | Independent per-stream selection and lifecycle; no sibling mutation |
| Shared source | All members update atomically and agree on identity |
| Semantic writer | Exact literal CAS; comments preserved; ambiguity rejected |
| Source handling | Origin/redirect/digest/authenticity evidence; same-ID change quarantined |
| Artifact handling | Ordered complete hash regeneration; hermetic final build |
| Worktrees | Human changes preserved; safe resume/adopt/cleanup |
| Agent | Typed bounded tools; no secret/Git/policy authority; forbidden repairs rejected |
| Validation | Quick affected feedback plus all final exact-head tests |
| Host limitations | Missing target/KVM/test capability remains action-required |
| Evidence | Complete bounded dossier, sanitized PR rendering, release boundary explicit |
| Publication | Explicit maintainer confirmation; expected remote head; no force/merge/release |
| Legal | Contributor authorization remains fail-closed; QEMU DCO never synthesized |

## Migration completion criteria

Write mode remains opt-in until:

- every package has a valid classification;
- automatic/assisted owner paths and fields are literal and unique;
- every consumed fixed-output input is represented or explicitly manual;
- all maintained concurrent streams have independent policy;
- frozen units have owners and non-expired review dates;
- direct provider and Repology mappings are reviewed;
- the local journal/worktree recovery suite passes failure injection;
- the semantic writer has no heuristic fallback;
- all supported materializers preserve hermetic final builds;
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
