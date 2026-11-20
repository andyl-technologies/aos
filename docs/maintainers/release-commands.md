# Release commands

This page documents the `aos maintain release` porcelain: the commands an
operator runs to plan a release, advance it to each destination, inspect and
review it, and record fitness attestations, together with the layout of the
release work directory. It is part of the
[canonical release coordinator](canonical-releases.md) reference; follow the
[release checklist](release-checklist.md) for the order of operations.

## Porcelain commands

```text
aos maintain release new --registry R --version V --images PATH [--release-id ID] [--override DIR] [--first-release --source-registry DIR] [--request-only] [--work DIR] [--config PATH]
aos maintain release advance --to <destination> [--ring N] [--override DIR] [--stop-after-upload [--stage-revision N]] [--accept-transaction] [--work DIR] [--config PATH]
aos maintain release publish --to <destination> [--stage-revision N] [--work DIR] [--config PATH]
aos maintain release status [--work DIR] [--config PATH]
aos maintain release explain --to <destination> [--work DIR] [--config PATH]
aos maintain release review [--reject --reason TEXT] [--work DIR] [--config PATH]
aos maintain release fitness run <kind> [--report PATH] [--config PATH]
aos maintain release fitness status [--config PATH]
```

A destination is `<surface role>/<channel>`, for example `staging/edge`,
`production/candidate`, or `production/stable`; the registry comes from the
plan. Every porcelain command accepts `--config PATH` to select the
[maintainer configuration](release-maintainer-machine.md#maintainer-configuration). Without `--work`,
commands that act on a release select the most recently created release under
the configuration's `work_root`; `new` defaults to `<work_root>/<release_id>`.

### Start a release

```sh
aos maintain release new --registry andyl/main --version 2026.10.0-rc.2 --images images.json
```

`--images PATH` is required. It names the reviewed Linux image decisions: a
strict JSON array with one entry per public system variant, each carrying an
explicit decision for both Linux architectures. It becomes the request's
`images` field unchanged. `--release-id` defaults to `release-<version>`.

`new` derives a complete `aos.release.plan-request/v1` from:

- the configuration's registry, source, policy, signer, and surface settings,
  including every `[signer.roles]` table and provider revision;
- the image decisions named by `--images`;
- live registry state read from the staging surface: the base commit and
  generation through Hub RPC for a `hub` surface, or from the registry head
  object at the root of a `static` surface;
- both surfaces' identities, checked against the live deployment or
  `.aos-surface`;
- the exported qualification contract;
- the change scope, computed against `predecessor_bundle`; and
- the destination set for the registry tier and the version's class.

It prints the request summary, runs the planner, and writes the work directory.
`--work DIR` selects a different location than `<work_root>/<release_id>`. The
command refuses a directory that already holds a frozen plan or belongs to
another release. Rerunning it after a failed planning attempt reuses the
unfinished directory only when the derived request is byte-identical;
otherwise remove the unfinished directory first. `--request-only` writes
`request.json` and stops before planning, so the derived request can be
reviewed first; rerun without it to freeze the plan from the same request.
`--override DIR` plans with signed
[profile overrides](#plan-an-emergency-override) from the start. The frozen
plan is the identity bound by every later operation. To change anything,
start a new release.

#### Plan a registry's first release

A registry that no surface serves yet has no publication from which to read a
base. Its first release plans the root commit of the authoring clone that
`apr create` wrote, and names that clone explicitly:

```sh
aos maintain release new --registry andyl/experimental \
  --version 2026.9.0-dev.20260927.1 --images images.json \
  --first-release \
  --source-registry ~/.local/share/apm/registries/andyl-experimental
```

`--first-release` and `--source-registry` require each other. `new` then
refuses to plan unless:

- the staging surface holds no publication of the registry at all: no
  publication in any state on a Hub, and no registry `HEAD` object on a
  static surface;
- the clone is a non-bare Git repository with SHA-256 object ids and no
  uncommitted or untracked changes;
- every reference in the clone, `HEAD` included, names one and the same
  parentless root commit; and
- the clone's `registry.toml` names the registry by its slash-free alias
  (`andyl-experimental` for `andyl/experimental`) or by its bare name
  (`experimental`).

The request plans that root commit at generation 0 and records
`"first_release": true`, and the summary's `Registry` row says so. Without
`--first-release`, `new` refuses a staging surface that holds no publication;
with it, `new` refuses one that does, so neither path can stand in for the
other. The flag is not part of the frozen plan: the signed bootstrap intents
bind the plan digest and its base commit instead.

A first release cannot publish until its base is installed on each surface.
Follow [Bootstrap the first registry base](release-step-commands.md#bootstrap-the-first-registry-base)
for staging and then production, writing each `step bootstrap` output to
`<work>/bootstrap/<role>/`. Until that directory holds bootstrap evidence for
the planned base, `advance` stops before anything reaches that surface with a
`Waiting:` instruction naming the exact `step bootstrap` invocation. Place the
same clean clone (or a copy at the same commit) at `inputs/source-registry/`
for `step prepare-registry`.

### Advance to a destination

```sh
aos maintain release advance --to staging/candidate
aos maintain release advance --to production/candidate
aos maintain release advance --to production/stable --ring 2
```

`advance` computes the next step from the journal and the work directory, runs
it, and repeats until the destination is published and complete or a human
decision is required. For a destination it performs, in order, whichever of
these steps are not already done:

1. `step build`, then `step finalize-image` for each planned Linux image cell;
2. `step prepare-registry` from the operator's `inputs/source-registry/` (and
   `inputs/container/` when the release carries an OCI artifact), the
   transaction review stop when a planned profile requires it,
   `step finalize-registry`, and `step finalize-cache`;
3. `step assemble` with the operator's `inputs/advisory-disposition.json`,
   `step finalize`, and `step verify`, recorded in `verification.json`;
4. for a production destination: `step qualify-run --phase staging` against
   the staging surface, review collection, and authority signing;
5. fitness validation for the destination's profile;
6. publication, in dependency order. The first destination published on a
   surface builds that surface's metadata for the release: `step record` (on
   the production surface), `step tuf` at the surface's next metadata
   versions, `step timestamp refresh` over the new snapshot, and
   `step compose-surface`. Then `step publish --to --surface` uploads the
   immutable part of the composed surface and reads it back, and
   `step timestamp publish` moves the surface's timestamp pointer to the new
   snapshot by compare-and-swap, so readers never follow a timestamp to
   metadata that is not yet served. A later destination on the same surface
   runs only `step publish`;
7. for each rollout ring: the previous ring's observation time,
   `step qualify-run --phase rollout` and review when the profile has a
   rollout gate, then `step channel advance --ring`; and
8. only when the profile selects `qualified` claims (`soak`): the soak,
   `step qualify-run --phase complete`, the completion approvals, then
   `step channel complete`.

Steps 1 to 3 run once per release, not once per destination. A destination
whose profile selects no `qualified` claims (`build`, `smoke`, and
`functional`) records `complete` automatically when its final ring's channel
advance and public read-back succeed; it needs no complete-phase qualification
and no completion approval. A staging destination therefore ends after step 6
plus its single ring, with no qualification at all. A second destination on a
surface that already holds the release's publication verifies that publication
by full read-back and moves only its own channel.

When a step needs a person, `advance` prints one instruction beginning
`Waiting:` and exits zero. The human steps are:

- for a [first release](#plan-a-registrys-first-release), the signed
  bootstrap of each surface into `bootstrap/<role>/`, before anything reaches
  that surface;
- operator inputs the driver cannot produce, each at a fixed path in the work
  directory: a clean authoring registry clone at the planned base commit in
  `inputs/source-registry/`, the externally signed OCI release bundle
  (`container-release.json`, `signature-input.json`, and `layout/`) in
  `inputs/container/`, and the reviewed advisory disposition for
  `build/evidence/sbom.spdx.json` in `inputs/advisory-disposition.json`;
- acceptance of the isolated registry transaction, when any planned
  destination's profile requires transaction review: inspect
  `registry/transaction.json` and `registry/prepared/`, then rerun with
  `--accept-transaction`, which records `registry/transaction-accepted.json`;
- reviews of a prepared qualification report and, for a `soak` destination,
  completion approvals, both signed with
  [`aos maintain release review`](#review-pending-decisions);
- fresh fitness attestations, recorded with
  [`aos maintain release fitness run`](#record-fitness-attestations); and
- observation windows: a ring's `observe_seconds` and the destination's soak.

`advance` is idempotent. It skips steps whose outputs exist and whose journal
state matches, and fails closed when an output exists but disagrees with the
journal. `--ring N` stops after ring `N` even when later rings are eligible;
rings are numbered from 1 in profile order. Without `--ring`, `advance`
continues through every ring whose prerequisites are met. `--override DIR` is
described in [plan an emergency override](#plan-an-emergency-override).

Failures exit nonzero and leave every completed output in place. Rerun after
the cause is fixed, following the release checklist's
[failure procedure](release-checklist.md#if-a-step-fails-or-is-interrupted).

### Inspect progress

```sh
aos maintain release status
aos maintain release explain --to production/stable
```

`status` reconciles the release's journal offline. It prints a `State:` line
with the global state, one `<destination>: <state>` line per planned
destination (a destination not yet published shows `pending`), and then a
`Next:` line naming the step `advance` would run, the pending `Waiting:`
instruction, or `Complete:` once every destination is complete.

`explain --to` prints everything that decides whether the destination can move:

- the profile, profile digest, and the soak and rings in force, marking values
  set by an accepted override;
- the change scope and the cases it selects, with each case's current result;
- reviews collected against the number required;
- each required fitness kind with its latest attestation, age, maximum age, and
  binding comparison; and
- the first unmet condition blocking the next step.

Neither command writes anything.

### Review pending decisions

```sh
aos maintain release review
aos maintain release review --reject --reason "container lifecycle log shows a retried stop"
```

`review` finds the single decision the release is waiting on and signs it with
the configuration's `[reviewer]` key through the configured signer:

- a prepared qualification report for a destination and phase: the command
  prints the plan digest, report digest, destination, phase, ring, and case
  results, then writes a signed `aos.release.qualification-review/v1` receipt
  to `qualification/<slug>/<phase>/review-<key_id>.json`; or
- the completion decision of a destination whose profile selects `qualified`
  claims (`soak`), after its final ring and complete-phase qualification: the
  command prints the rollout receipts and retention policy, then writes a
  signed `aos.release.completion-receipt/v1` approval to
  `channels/<slug>/completion-<key_id>.json`. Later approvers sign the same
  decision bytes after the command checks that they still describe the
  current rollout.

`--reject --reason TEXT` signs a report review with `accepted: false` and
stores the reason beside it as `review-<key_id>.reason.txt`. A rejected report
cannot be admitted; `advance` moves it aside and recollects it. Completion
decisions are approvals only: `--reject` is refused for them, so withhold the
approval and record the reason in the operator log instead. Run `review` as
the reviewer, not as the operator who collected the report. Where a threshold
needs several reviewers, each runs `review` with their own configuration and
key.

### Plan an emergency override

An emergency relaxes only `production/stable` soak and rings through a signed
[profile override](qualification.md#profile-overrides). The plan references
the override, so it must be supplied before anything is built:

1. Record the incident. Write the override payload for the new release ID and
   `production/stable`.
2. Obtain one signed envelope per release-evidence signer, for example with
   `aos-release-signer sign-evidence --key-id KEY --payload override.json
   --output approvals/override-1.json`, until the role threshold is reached.
3. Run `aos maintain release new ... --override approvals/`, or run `aos maintain release new`
   and then immediately:

   ```sh
   aos maintain release advance --to production/stable --override approvals/
   ```

`DIR` names the directory holding the signed envelopes. Either command verifies
the envelopes against the release-evidence keys in `[signer.roles]`, the
planned threshold, and the profile's override policy. `advance --override`
works only while nothing has been built: it re-freezes the plan with the
override's digest and the relaxed soak and rings and retains the superseded
plan as `plan.superseded-<n>.json`. Once the release is built, `--override` is
rejected; start a new release instead.

### Record fitness attestations

```sh
aos maintain release fitness run authority-recovery --report /srv/aos-release/restricted/authority-recovery-2026-09-14.json
aos maintain release fitness run hub-restore < /srv/aos-release/restricted/hub-restore-2026-09-14.json
aos maintain release fitness status
```

`fitness run` reads one strict JSON `aos.release.fitness-report/v1` exercise
report from `--report PATH`, or from standard input when `--report` is absent:

```json
{"checks":{"isolated-hub-restore":{"detail":"Restored rp-0914 into hub-restore-test.","passed":true}},"operator":"dplecki","performed_at":"2026-09-14T15:00:00Z","schema_version":"aos.release.fitness-report/v1"}
```

The report must name exactly the checks of one
[fitness kind](qualification.md#fitness-attestations), each passed with a
detail, a UTC performed time, and the operator; the example shows one check for
brevity. The command then reads the live binding values, signs an
`aos.release.fitness-attestation/v1` with a release-evidence key through the
configured signer, and writes it to `<fitness_root>/<kind>/<performed_at>.json`
without replacing an existing file. The signing key is the `[reviewer]` key
when that section is present, else the single configured `release-evidence`
key. The report stays in restricted storage; the attestation carries its
digest.

Neither `fitness run` nor `fitness status` needs a frozen plan. The fitness
kinds and profiles come from the newest release plan under `work_root` when
one exists, else from that work directory's `contract.json`, else from the
repository's Nix contract export (the `step contract` leaf, so run the command
from the AOS checkout before the first `aos maintain release new`). Attestations are
verified against the configured `[signer.roles.release-evidence]` keys; only
when that table is absent does the newest plan's frozen roster apply, and with
neither the command refuses to run. Without a plan, `fitness status` lists no
destinations.

Binding values come from the configuration: `surface` and `hub-schema` from
`[surfaces.production]` and its live deployment, `signer-roster` from the
`[signer.roles]` tables that `new` freezes into each plan's signer list,
`tooling` from the [release tooling environment](release-maintainer-machine.md#release-tooling-environment),
and `alert-config` from `[alert]`. The
maintainer machine's restore-check and alert-check services call
`fitness run` for the automated kinds.

`fitness status` prints each kind's latest attestation, its age, the maximum
age each profile accepts, the binding comparison, and which destinations it
currently satisfies or blocks.

### Work directory layout

`new` creates `<work_root>/<release_id>/`:

```text
release.toml                      index: registry, version, release_id,
                                  config digest, created_at, latest_journal
request.json                      derived aos.release.plan-request/v1
plan.json                         frozen aos.release.plan/v1
plan.superseded-<n>.json          plans replaced by an accepted override
contract.json                     exported contract the request binds
contributor-authorization.json    public summary bound by the plan
inputs/source-registry/           operator: clean authoring registry at the base
inputs/container/                 operator: signed OCI release bundle
inputs/advisory-disposition.json  operator: reviewed advisory disposition
bootstrap/<role>/                 operator: step bootstrap output of a first
                                  release (signed-intents/, bootstrap-evidence.json)
build/                            build report, SBOM, build journal
images/<platform>/<variant>/      finalize-image work and finalized/ output
registry/prepared/                isolated registry, finalized in place
registry/transaction.json         transaction for operator review
registry/transaction-accepted.json
                                  operator acceptance recorded by advance
registry/result.json              finalize-registry result
cache/                            signed static cache
assembled/                        closed unsigned payload and manifest payload
finalized/bundle/                 signed bundle
finalized/release-journal.jsonl
verification.json                 offline verification record
publish/<slug>/release-record.json
                                  step record (first production destination)
publish/<slug>/tuf/metadata/      step tuf at the surface's next versions
publish/<slug>/tuf/surface-state.json
                                  surface TUF state the versions came from
publish/<slug>/timestamp/         one timestamp attempt: previous-timestamp.json
                                  (served), timestamp.json (step timestamp
                                  refresh), surface/ (step compose-surface),
                                  overlay/ (immutable subset step publish
                                  uploads), published/ (step timestamp publish)
publish/<slug>/timestamp.retired-<n>/
                                  expired timestamp attempts moved aside
publish/<slug>/published/         receipt.json, release-journal.jsonl
qualification/<slug>/<phase>/     prepared/, review-<key_id>.json, signed/
qualification/<slug>/<phase>.retired-<n>/
                                  rejected or stale attempts moved aside
channels/<slug>/ring-<n>/         channel-receipt.json, release-journal.jsonl
channels/<slug>/completion-<key_id>.json
                                  completion approvals (soak destinations)
channels/<slug>/complete/         completion evidence and journal
journal.jsonl                     symbolic link to the latest journal
```

`<slug>` is the destination name with `/` replaced by `-`, for example
`production-stable`. `<phase>` is `staging`, `rollout-<ring>`, or `complete`.
Only the first destination published on a surface writes `tuf/` and
`timestamp/`; a later destination on the same surface has only `published/`.
When a refreshed timestamp expires, or would expire, before it is published,
`advance` moves the whole attempt aside as `timestamp.retired-<n>/` and signs a
new one.

Every file is written once, except `release.toml` and the `journal.jsonl`
link, which the driver replaces atomically as the release advances. Successor
journals appear beside the step that produced them; `release.toml` names the
latest. Back up the whole directory with the other operator state.

## Stop after upload and publish the reviewed destination

The registry pipeline distinguishes unpublished candidate upload from public
release visibility and channel movement. A staging deployment is an environment;
an unpublished stage is a candidate revision on either environment.

Use the porcelain to retain a destination's uploaded immutable artifacts before
publication:

```sh
aos maintain release advance --to staging/edge \
  --stop-after-upload --work "$WORK" --config "$CONFIG"
aos maintain release status --work "$WORK" --config "$CONFIG"
aos maintain release explain --to staging/edge \
  --work "$WORK" --config "$CONFIG"
```

After reviewing the retained inventory and destination obligations, publish the
exact candidate:

```sh
aos maintain release publish --to staging/edge \
  --work "$WORK" --config "$CONFIG"
```

Use `--stage-revision N` on `publish` to bind the inspected revision explicitly.
An identical upload resume preserves its revision. If recomposition changes the
candidate inventory, such as renewing its timestamp, repeat `advance
--stop-after-upload --stage-revision N` with the observed current revision;
without that precondition the changed candidate fails closed.

Continue qualification and channel rollout with `advance`. Production still
requires the exact staged bytes and the planned qualification evidence. Shared
registry libraries drive both this AOS-specific orchestrator and the stable
`apr release <version>` command. The previous `aos release` command is removed
without a compatibility alias. See
[registry release stages](../engineering/registry/release-stages.md) for discovery,
concurrency, and retention boundaries.
