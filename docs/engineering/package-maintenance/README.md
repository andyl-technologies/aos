# Package maintenance

`aos maintain` updates AOS packages through a local, resumable transaction:
declared upstream metadata, a discovery snapshot, an immutable plan, an
isolated worktree, deterministic edits, optional confined repair, quick and
final gates, and an explicitly published pull request. The operator workflow is
in [Upgrade packages with `aos maintain`](../../maintainers/package-upgrades.md).
The [update contract](update-contract.md) describes the package metadata the
tool reads and edits.

## Model

| Term | Meaning |
|---|---|
| Upstream family | Reporting grouping for one upstream project, such as `bazel` |
| Stream | One independently versioned compatibility line within a family, such as a major version |
| Update unit | The smallest schedulable object: one family stream, its components, and every package member that must agree on them (for example `zlib-1`) |
| Member | An evaluated package attribute produced from a unit; a shared source can feed several members |
| Component | An independently versioned upstream input within a unit, with its own discovery provider, release policy, and source slots |
| Source slot | A component's fetch contract: URL templates, hash mode, current hash, and allowed redirect hosts |
| Artifact slot | A fixed-output input derived from a source, such as vendored Cargo, Go, npm, or Bazel dependencies |
| Campaign | The transaction for one or more units that must land together; the default campaign has one unit |
| Run and attempt | A run executes one campaign from one base commit; each edit or repair creates a new attempt rather than overwriting evidence |

Concurrent major versions are separate units in one family and do not have to
update together; units that must land atomically form an explicit cohort.

## Components

| Path | Role |
|---|---|
| `pkgs/build-support/_upstream.nix` | `mkUpstream`, the validated update contract |
| `pkgs/build-support/_github-upstream.nix`, `_manual-upstream.nix` | Concise constructors for single-source GitHub units and human-led units |
| `pkgs/default.nix` | Collects every package's unit, supplies fallback units, and exports `maintenanceInventory` |
| `crates/release/aos-package-maintenance` | Pure contracts: identities, inventory, envelope, discovery, plan, workflow, agent boundary, and presentation. No I/O |
| `crates/cli/aos-cli/src/commands/maintain/` | The controller: inventory evaluation, discovery adapters, materialization, mutation, worktrees, gates, repair, ready-for-PR verification, Git, and GitHub |

Common canonical JSON, digest, and bounded-decoding primitives come from
`aos-core`, shared with the release format crates.

## Inventory and envelope

Pure Nix evaluation emits a closed inventory of every unit. Packages declare
their unit in `passthru.aos.maintenance` through the update contract. Packages
without one receive a fallback unit: frozen for deliberately pinned bootstrap
inputs, otherwise a manual unit whose reason says that updates need a
maintainer-authored plan. Units with the same identity across members must
agree. The controller wraps the inventory in an envelope binding it to the
exact Git commit, tree, dirty state, canonical remote, and common directory it
evaluated, so later steps can detect that the checkout moved.

## Discovery and planning

Discovery adapters query only the declared primary provider of each component
(`github-releases`, `github-tags`, or `go-releases`) and apply its release
policy: `latest-in-series`, `channel`, or `vcs-lineage` selection under a
`semver`, `numeric`, or `provider` version scheme, with optional series bounds,
prerelease exclusion, and a minimum release age. Repology is an advisory source
that can flag a unit but never selects a candidate. Snapshots are stored by
digest.

A plan (`PackageUpdatePlanV1`) freezes the selected component vector, the
semantic mutations it permits, the materializers, the risk level, and the quick
and final gate sets. Plans are immutable and addressed by digest; executing
one requires confirming that digest.

## Mutation and materialization

Edits are compare-and-swap rewrites of `mkUpstream` literals
(`commands/maintain/mutation.rs`): the editor parses the Nix file, checks that
each target field still has its planned preimage, and preserves comments. No
filename guessing or regular-expression edits are involved. Materialization
fetches sources, verifies hashes and redirect hosts, then regenerates declared
artifact slots in dependency order. The resulting repository diff must match
the plan before the run reaches `policy-valid`.

`refresh-hashes` (`commands/maintain/hash_refresh.rs`) is the path for
packages without a typed contract: it swaps one known fetcher hash at a time
for the placeholder hash, realizes the fixed-output derivation, and restores
the file on any failure.

## Workflow states

`aos-package-maintenance::workflow::RunState` defines the durable states and
their legal transitions:

```text
observed -> selected -> planned -> worktree-ready -> materializing
  -> policy-valid -> quick-gated [-> repairing] -> candidate-accepted
  -> committed -> final-gated -> ready-for-pr -> pr-published
  -> awaiting-remote-authorization -> merge-eligible-observed
  -> merged-observed -> release-handoff
```

Terminal and side states are `no-change`, `superseded`, `blocked-human`,
`quarantined`, `rejected`, `abandoned`, and `failed`. Each transition is a
hash-chained journal event. Results are commit-specific: an edit or rebase
invalidates earlier gate results, and unavailable or inconclusive required
gates leave a run incomplete.

`prepare-pr` (`commands/maintain/readiness.rs`) owns the
`final-gated -> ready-for-pr` transition. It verifies that the retained
materialization, the accepted repair lineage, successful quick gates bound to
the accepted patch digest, and successful final gates bound to the exact
candidate commit describe one candidate. Pull-request drafts and publications
bind the canonical digest of the final gate results; no separate evidence
dossier is written.

## Confinement and repair

Candidate evaluation, networked materialization, gates, and repair adapters
run under `commands/maintain/confinement.rs`: private user, mount, PID, IPC,
UTS, and network namespaces combined with the AOS Landlock wrapper and an
explicit read/write filesystem policy. When either primitive is unavailable the
command fails; it never falls back to an ordinary subprocess. Gate subprocesses
get a sanitized environment and bounded logs.

Repair is provider-neutral. The controller sends an `AgentTaskV1` describing a
typed failure and a bounded write scope to a local adapter executable over
JSON stdin and stdout, and receives an `AgentResultV1` proposal. The adapter
receives no Git, GitHub, release, signing, SSH-agent, or unrelated filesystem
authority, and a proposal changes the worktree only after the maintainer
confirms its patch digest. An adapter that needs more readable or writable
scope returns a scope request, which takes effect only in a later task the
maintainer approves. The result never selects releases, mutates Git, accepts
candidates, or decides gate outcomes.

## Publication

Git commits use the maintainer's identity. GitHub publication
(`commands/maintain/remote.rs`) pushes only the exact final-gated branch head
after a compare-and-swap check on the expected remote head, and PR observation
is read-only. The tool never merges, signs, or publishes packages; the release
flow independently rebuilds and qualifies the merged source.
