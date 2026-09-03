# Goals and workflow model

## Problem

AOS owns a large, entirely self-contained source package set. Maintaining it
requires more than comparing a version string:

- upstreams publish through different forges, registries, directories, tags,
  branches, and version schemes;
- some package attributes share one source release;
- some upstream families intentionally expose several major versions at once;
- generated Cargo, Go, npm, and Bazel inputs add fixed-output identities;
- patches, dependencies, flags, tests, and licenses can change with a release;
- bootstrap, kernel, init, crypto, QEMU, and Crucible updates require wider or
  exceptional validation;
- the final change must preserve AOS's no-nixpkgs, source-built, hermetic
  package boundary.

The maintainer currently has useful individual primitives—package evaluation,
source prefetching, formatting, linting, builds, and layered tests—but no single
transaction that explains what is stale, performs an update, repairs it, proves
the result, and preserves enough state to resume or review the work.

## Goals

1. Give a maintainer an accurate inventory of current, stale, unknown, frozen,
   manual, and unsupported upstream release streams.
2. Encode strong, reviewable associations between an upstream identity and the
   AOS source values that implement it.
3. Perform conventional version, URL, source-hash, and generated-input updates
   deterministically.
4. Use an agent for contextual repair without giving it authority over policy,
   credentials, completion, or publication.
5. Select fast tests from the evaluated dependency/check graph and run the
   complete required suite before declaring a PR ready.
6. Preserve a local, inspectable, resumable record of every observation, edit,
   agent proposal, command, result, and maintainer decision.
7. Let the maintainer stop, edit manually, continue, abandon, or publish at any
   stage.
8. Produce a small, ordinary branch and PR that enters the existing human
   review and contributor-authorization path.
9. Hand the merged protected commit to RFC-0017 without coupling the iterative
   update transaction to release state.

## Non-goals

- Automatically merging a package update.
- Publishing packages, images, channels, signatures, or registry state.
- Replacing RFC-0017's release plan, evidence, qualification, or signing.
- Making Repology or another aggregator authoritative for upstream identity.
- Importing nixpkgs, executing nixpkgs tooling, or preserving compatibility
  with nixpkgs package-update conventions.
- Running arbitrary package-authored update scripts.
- Making every Nix expression mechanically editable.
- Solving dependency feature regressions by disabling functionality.
- Hiding unavailable, flaky, skipped, or inconclusive validation.
- Requiring a background process or remotely operated execution environment.
  Networked materializers, candidate evaluation, tests, and agent tools may
  require a verified local confinement backend and fail closed without it.

## Terminology

### Upstream family

A reporting and lifecycle grouping for one upstream project. `bazel` is a
family. A family can contain several simultaneously maintained streams.

### Stream

An independently versioned compatibility line selected by declared policy:
major, minor, LTS branch, named channel, or snapshot lineage. Bazel major 8 and
major 9 are different streams.

### Update unit

The smallest schedulable package-policy and source-mutation object. It owns a
complete component vector and all package members that must agree on it. Its
stable ID usually combines family and stream, such as `bazel-8` or
`linux-6.18`. A campaign owns worktree, branch, validation, and PR atomicity for
one or more units.

### Member

An evaluated AOS package attribute produced from a unit. A unit can have one
member or many. `linux` and `linux-headers` are separate members of one shared
source unit.

### Component and source slot

A component is an independently versioned upstream input within a unit. It owns
its current identity, discovery provider, stream policy, candidate, and source
slots. A source slot is its fetch contract: URLs, hash mode, current hash,
allowed origins, and assurance requirements. The unit's package version is a
separate typed projection of one or more component identities.

### Artifact slot

A fixed-output input derived from a source slot, such as vendored Cargo crates,
Go modules, npm dependencies, Bazel dependencies, generated lock data, or a
platform-specific dependency archive.

### Cohort

Several otherwise separate update units that must land atomically. This is
distinct from family membership. Concurrent major versions are normally a
family, not a cohort.

### Campaign

The transaction created for one or more unit candidates. The default campaign
contains one unit. An explicit cohort or an approved new-dependency expansion
creates a multi-unit campaign with one plan, worktree, journal, gate set,
branch, and PR.

### Run and attempt

A run executes one campaign from one base commit. Its target is a component-
version vector for every included unit plus each resulting package version. An
attempt is one reconstructible edit/validation generation inside the run.
Agent or human edits create new attempts rather than overwriting earlier
evidence.

## Package archetypes

The contract and fixture corpus must cover at least these repository shapes:

| Archetype | Representative AOS shape | Required behavior |
| --- | --- | --- |
| Conventional source | One literal version, URL template, and source hash | Fully deterministic update |
| Shared source | [`kernel/_source.nix`](../../../pkgs/kernel/_source.nix) feeds `linux` and `linux-headers` | One unit, several members, one atomic source change |
| Concurrent majors | `bazel-7`, `bazel-8`, and `bazel-9` | Separate unit/policy per major; all may ship together |
| Cargo input | Source hash plus Cargo vendor/dependency hash and patches | Ordered source then artifact materialization |
| Multiple Go modules | One source plus several `fetchGoModules` inputs | All hashes updated atomically |
| npm/composite | Local lock/manifest transformations and independently versioned upstream components | Component target vector plus declared generated-output CAS |
| Platform-specific | Different source or dependency inputs by target | Explicit target-conditioned slots and all-target validation |
| Bootstrap ladder | Intentionally retained compiler/tool versions | Explicit supported/frozen/cohort policy, never global-latest comparison |
| Curated source collection | SDK or package with many independently pinned revisions | Manual or assisted components with a closed plan |
| QEMU/Crucible | Patch series, source bundle, ABI/license boundary, corresponding source | Exceptional human-led update with mandatory gates |
| Alias/wrapper | Default name points at a maintained versioned package | Non-schedulable member owned by another unit |

The evaluated source graph, not this table, is the final authority. The initial
inventory implementation must count and classify the actual tree before write
mode is enabled.

## Maintainer experience

The normal loop is intentionally inspectable:

```text
$ aos maintain scan
$ aos maintain report --outdated
$ aos maintain plan bazel-8
$ aos maintain run bazel-8
$ aos maintain inspect <run-id>
$ aos maintain resume <run-id>
$ aos maintain publish-pr <run-id>
```

`scan` and `report` are read-only. `plan` closes the campaign's unit/component
candidate vector, edit surface, materializers, risk, and tests without changing
the checkout. `run` creates a dedicated worktree and advances until completion,
a human decision, or an explicit budget. `inspect` shows both human-readable
and machine-readable state. `resume` verifies all durable preconditions before
continuing.
`publish-pr` is a separate, explicit action that uses the maintainer's normal
Git identity and authentication only after the maintainer reviews the exact
branch, commit message, PR text, and evidence.

Every command has stable `--json` output. High-level commands are compositions
of lower-level operations so maintainers can diagnose or repeat one stage:

```text
aos maintain inventory
aos maintain discover
aos maintain select
aos maintain materialize
aos maintain repair
aos maintain test
aos maintain evidence
```

The commands do not need to remain running between stages. State survives shell
exit, machine reboot, and ordinary Git inspection.

## Workflow principles

### Show work early

Create a worktree as soon as a plan is accepted. A maintainer can inspect the
patch and logs while the run is incomplete. Do not require a hidden end-to-end
operation before useful output exists.

### Fail with a typed next action

Failures distinguish upstream ambiguity, source anomaly, plan staleness,
unsupported mutation, build failure, package-test failure, unavailable host
capability, policy block, agent budget, and ordinary interruption. Each class
has a safe resume, re-plan, human-review, or abandon action.

### Preserve human changes

If a maintainer edits the worktree, the tool records the new tree as a human
attempt after confirmation. It never regenerates over an unknown head. A new
base or target produces a new plan generation and invalidates old test results.

### Prefer evidence over narration

The final PR summary is generated from structured observations, semantic edits,
Git identities, and test results. Free-form agent text is supplementary and
cannot satisfy a gate.

### Make composition cheap

Stable schemas, deterministic exit codes, explicit paths, foreground execution,
and idempotent subcommands make the local tool useful in shell workflows and
editor integrations without changing its core semantics.

## Success criteria

The first useful milestone is not autonomous repair. It is a trustworthy local
tool that can:

- classify the whole package set;
- report current and stale maintained streams with evidence;
- update a conventional source unit and every declared fixed-output input;
- prove exactly which semantic fields changed;
- select and run the correct affected package/check graph;
- survive interruption and resume safely;
- leave an ordinary inspectable Git worktree and evidence dossier.

Agent assistance and PR publication build on that foundation after the
deterministic path is proven.
