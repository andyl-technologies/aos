# Canonical release coordinator

Each registry carries its own channels. `andyl/main` carries `edge`,
`candidate`, and `stable`. `andyl/experimental`, and each `andyl/experimental-vN` epoch,
carries `edge` only. Main requires strict build and publication provenance for
every channel; the experimental registry isolates the experimental pipeline and its keys. The experimental registry
releases never become main releases by changing a channel or copying signed
artifacts.

Disk images and OCI containers must configure APM for their exact publishing
registry. The shared `aos.release` profile supplies the registry URL
(`<registryOrigin>/<registry>/`, by default
`https://cdn.aos.andyl.org/<registry>/`), the default Hub (`hubUrl`), trust
alias, root epoch, channel, and experimental notice. Planning, building, and image
finalization check this profile from the clean source commit frozen in the
plan, on every selected platform. A experimental profile fails a main plan and vice
versa. Every image's baked `hubUrl` must equal the origin of the Hub surface
consumers will install from: the production surface when the plan has any
production destination (the same signed bytes reach production, and staging
exercises them with an explicit cache override), or the staging surface for a
staging-only plan. Build the `aos-experimental-staging` variant for staging-only
plans on the canonical staging Hub, as described in
[the Hub deployment guide](aos-hub-deployment.md#build-artifacts-for-the-staging-destination).
A static surface has no Hub origin to bind. Package
transactions, manifests, evidence, and channel receipts bind the same registry;
packages inherit their client's configured registry when installed. Inspect the
destinations and their obligations with
`aos maintain release step contract --registry andyl/experimental` or
`--registry andyl/main` before starting a release.

Start with the [release checklist](release-checklist.md) for the order of
operations and the conditions for proceeding. This page is the command reference;
the [qualification specification](qualification.md) defines destinations,
profiles, fitness attestations, and the evidence. New plans embed the
source-controlled contract in `aos.release.plan/v1`.

Canonical AOS releases are driven by one reviewed plan. The plan freezes the
source revision, registry base, complete package and image matrices, signer
roles, both publication surfaces, every destination with its profile digest,
gates, soak, and rollout rings, the change scope, any accepted profile
override, and the retention policy before a build or signing effect occurs.

The role boundaries and compromise implications behind this procedure are
defined in [Maintain the AOS trust model](trust-model.md).

The command surface has two layers:

- **Porcelain.** `aos maintain release new`, `advance`, `publish`, `status`, `explain`, `review`,
  and `fitness` operate a release from the
  [maintainer configuration](#maintainer-configuration) and a
  [work directory](#work-directory-layout). They are the normal interface.
- **Steps.** `aos maintain release step ...` exposes each fail-closed operation with
  explicit inputs. The porcelain calls the same functions in process; it never
  spawns itself. Use steps directly for recovery, audit, qualification
  snapshots, and inspection of captured evidence.

Every operation is fail-closed. A surface may be an AOS Hub deployment or a
[static origin](#static-surfaces); no command requires a Hub unless the plan
names one.

Supported publication to `andyl/main` remains forbidden until the remaining
RFC-0017 launch gates are complete. The experimental `andyl/experimental` registry
may be published to its production surface only under
[`registry-experimental.md`](registry-experimental.md); that does not satisfy or bypass
any main-registry launch gate.

The canonical release image profile enables external Secure Boot, distinct
module and PCR-policy roles, lockdown, measured boot, encrypted state,
dm-verity, signed recovery, audit, firewalling, and the hardened runtime
preset. It deliberately reports SELinux as excluded: the current immutable
root is not pre-labeled, so enabling the existing policy would overstate the
MAC boundary. SELinux may enter the production profile only with labeled-root
construction and an enforcing boot qualification gate.

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
[registry release stages](../registry/release-stages.md) for discovery,
concurrency, and retention boundaries.

## Configure the designated maintainer machine

Enable `aos.services.releaseCoordinator` only in the private machine
configuration. Supply six hermetic wrapper programs: the manually started
content-release driver, restricted TUF timestamp renewal, encrypted backup,
clean-directory restore verification, operator alert delivery, and the
alert-delivery check. The public module deliberately contains no machine
identity or deployment-specific path.

The module creates distinct locked service accounts and state directories,
loads each role's disjoint credentials with systemd's credential mechanism,
and rejects credential sources in the Nix store. Content publication has no
timer and begins only with an operator start of
`aos-release-coordinator.service`; this is the no-CI control point. Timestamp
renewal runs every 12 hours by default, backup runs daily, and an offline
network-denied restore check runs weekly. Override calendars only if the TUF
expiry and recovery objectives remain satisfied.

A weekly `aos-release-alert-check.service` runs as the alert role, triggers
the alert path with a synthetic unit name, confirms delivery, and records a
signed `alert-delivery` fitness attestation; a successful restore check
likewise records `storage-restore`. Both land under `fitnessRoot` (default
`/var/lib/aos-release-coordinator/fitness`), a setgid directory writable by
the `aos-release-fitness` group so the release, backup, and monitor roles can
each write there, and are signed with the release-evidence signer loaded from
`fitnessCredentials`. Production destination profiles accept these machine-run
attestations for at most 14 days; operator exercises are recorded manually
with `aos maintain release fitness run <kind>` and remain valid for 90 days.

Every failed release, timestamp, backup, restore, or alert-check unit invokes
the isolated alert service with only the failed unit name and alert-role
credentials.
The content-release, backup, and restore jobs share a nonblocking advisory lock;
an overlap fails closed and alerts instead of taking an inconsistent snapshot.
Timestamp renewal uses separate state, identity, policy, and credentials and
does not acquire the content-state lock.

Deployment wrapper programs receive no command-line secrets. They resolve
credential names beneath `$CREDENTIALS_DIRECTORY`, write only beneath their
assigned state/runtime directories, and exec the documented `aos maintain release`
commands. Keep staging and production upload credentials in different
operator steps; do not place both in the manual service's credential set at
the same time.

## Porcelain commands

```text
aos maintain release new --registry R --version V --images PATH [--release-id ID] [--override DIR] [--work DIR] [--config PATH]
aos maintain release advance --to <destination> [--ring N] [--override DIR] [--accept-transaction] [--work DIR] [--config PATH]
aos maintain release status [--work DIR] [--config PATH]
aos maintain release explain --to <destination> [--work DIR] [--config PATH]
aos maintain release review [--reject --reason TEXT] [--work DIR] [--config PATH]
aos maintain release fitness run <kind> [--report PATH] [--config PATH]
aos maintain release fitness status [--config PATH]
```

A destination is `<surface role>/<channel>`, for example `staging/edge`,
`production/candidate`, or `production/stable`; the registry comes from the
plan. Every porcelain command accepts `--config PATH` to select the
[maintainer configuration](#maintainer-configuration). Without `--work`,
commands that act on a release select the most recently created release under
the configuration's `work_root`; `new` defaults to `<work_root>/<release_id>`.

### Release tooling environment

The coordinator never reads its own store path or the qualification
executors from the maintainer configuration. Both come from the installed
tooling closure, the flake's `release-tooling` package: its `bin/aos`
wrapper exports `AOS_RELEASE_TOOLING` naming the closure, and the closure
carries one executor per platform it can qualify at
`libexec/aos-release/executors/<platform>/{run,identity}`. Enter it with
`nix develop .#release`, or install it as the `aos` every coordinator
service wrapper runs.

Without the wrapper, `aos maintain release` falls back to the `/nix/store/<name>`
root containing its own executable. A binary outside the store, such as a
development `cargo build`, has no closure: it can inspect state, but `new`,
`advance`, and every qualification step refuse to run from it. The closure
path is the `tooling` fitness binding, so all maintainer roles on a machine
must run the same closure or the restore check's attestation will not match
the operator's release.

### Maintainer configuration

The porcelain reads one `aos.release.maintainer-config/v1` TOML file: the path
in `$AOS_RELEASE_CONFIG`, else `/etc/aos-release/maintainer.toml`, else
`~/.config/aos/release.toml`. `--config` overrides the search. One
configuration serves one registry, so experimental and main keep separate files,
state directories, and credentials. Unknown keys are rejected.

```toml
schema_version = "aos.release.maintainer-config/v1"
work_root = "/var/lib/aos-release-coordinator/releases"
fitness_root = "/var/lib/aos-release-coordinator/fitness"
registry = "andyl/experimental"
protected_branch = "master"
contributor_authorization = "/etc/aos-release/release-contributor-authorization.json"
retention_policy = "/etc/aos-release/release-retention-policy.md"
restricted_operator_policy = "/etc/aos-release/restricted-operator-policy.md"
predecessor_bundle = "/var/lib/aos-release-coordinator/predecessor"
trusted_keys = ["release-evidence-v1=/etc/aos-release/keys/release-evidence-v1.pub"]

[git]
name = "AOS Release"
email = "release@aos.andyl.org"

[surfaces.staging]
kind = "hub"
origin = "https://aos.staging.andyl.org"
identity = "staging-2026-09"
receipt_keys = ["staging-publication-v1=/etc/aos-release/keys/staging-publication-v1.pub"]
# Optional: without it, AOS_TOKEN, else the active `aos hub login` profile
# for this origin (see "Hub credentials" below).
token_credential = "staging-token"

[surfaces.production]
kind = "static"
origin = "s3://aos-registry/andyl-experimental"
readback_origin = "https://cdn.example.org/andyl-experimental"
identity = "cdn-2026-09"
s3_region = "auto"
s3_endpoint = "https://s3.example.org"

[signer]
executable = "/etc/aos-release/bin/signer"
timeout_seconds = 900
provider_revision = "provider-2026-09"

[signer.roles.registry]
key_id = "registry-v1"
public_key = "/etc/aos-release/keys/registry-v1.pub"
verification_identity = "provider-registry-slot"

[signer.roles.surface-receipt]
key_id = "surface-v1"
public_key = "/etc/aos-release/keys/surface-v1.pub"
verification_identity = "provider-surface-slot"

[signer.roles.release-evidence]
threshold = 2
keys = [
  { key_id = "release-evidence-v1", public_key = "/etc/aos-release/keys/release-evidence-v1.pub", verification_identity = "slot-1" },
  { key_id = "release-evidence-v2", public_key = "/etc/aos-release/keys/release-evidence-v2.pub", verification_identity = "slot-2" },
]

[tuf]
root = "/etc/aos-release/tuf/root.json"
trusted_root_keys = ["root-v1=/etc/aos-release/keys/root-v1.pub"]
trusted_root_threshold = 1

[reviewer]
key_id = "release-evidence-v1"
public_key = "/etc/aos-release/keys/release-evidence-v1.pub"

[alert]
program = "/etc/aos-release/bin/alert"
destination = "oncall@example.org"
```

| Key | Meaning |
| --- | --- |
| `schema_version` | Exactly `aos.release.maintainer-config/v1` |
| `work_root` | Private directory holding one work directory per release |
| `fitness_root` | Directory holding fitness attestations as `<kind>/<performed_at>.json`; shared by every release of this registry |
| `registry` | The registry this configuration publishes; `new --registry` must equal it |
| `protected_branch` | Protected source branch; only `master` is accepted |
| `contributor_authorization` | Public contributor-authorization summary whose digest the plan binds |
| `retention_policy` | Retention policy document whose digest the plan binds |
| `restricted_operator_policy` | Restricted operator policy whose digest the plan binds without publishing it |
| `predecessor_bundle` | Verified signed bundle of the preceding release, used for the qualification predecessor, image update cases, and change scoping |
| `trusted_keys` | Independently obtained `KEY_ID=PATH` manifest verification keys |
| `git.name`, `git.email` | Required public author and committer of the registry release commit and tag. Both are published in the registry; use the maintaining organization's release identity, not a person's. The name may not contain control characters or angle brackets, and the email must be one address |
| `surfaces.<role>.kind` | `hub` or `static` |
| `surfaces.<role>.origin` | Hub origin, or static origin `file://`, `s3://`, or `sftp://` URL |
| `surfaces.<role>.readback_origin` | Anonymous `https://` or `file://` origin used for read-back when `origin` is not anonymously fetchable; required for `s3://` and `sftp://` |
| `surfaces.<role>.identity` | Hub deployment ID, or the static identity served at `.aos-surface` |
| `surfaces.<role>.receipt_keys` | `KEY_ID=PATH` keys that verify the surface's publication and channel receipts: Hub receipt keys, or the `surface-receipt` role key for a static surface |
| `surfaces.<role>.token_credential` | Optional Hub access token: a name under `$CREDENTIALS_DIRECTORY`, or an absolute path. See [Hub credentials](#hub-credentials) for the order in which it, `AOS_TOKEN`, and the `aos hub login` profile apply |
| `surfaces.<role>.s3_region`, `s3_profile`, `s3_endpoint` | S3 client settings for an `s3://` origin; credentials come from the AWS default chain |
| `surfaces.<role>.ssh_key_credential`, `ssh_password_credential` | SFTP private key or password for an `sftp://` origin |
| `surfaces.<role>.hub_schema` | Hub schema version the surface reports; the production value is the `hub-schema` fitness binding. Hub surfaces only |
| `signer.executable`, `signer.timeout_seconds` | External signer adapter and per-operation bound, 1 to 900 seconds (default 900) |
| `signer.provider_revision` | Provider policy revision frozen into every planned signer role that names none |
| `signer.roles.<role>` | One table per signer role in the plan, keyed by the role's public spelling, such as `registry`, `release-evidence`, `qualification`, `surface-receipt`, or `tuf-timestamp`. `new` freezes every table into the plan's signer roster in role-name order |
| `signer.roles.<role>.key_id`, `public_key`, `verification_identity` | Single-key form: key ID, independent public key, and pinned provider identity; means one key with threshold 1 |
| `signer.roles.<role>.keys`, `threshold` | Multi-key form: a list of `{key_id, public_key, verification_identity}` tables and the number of distinct signatures required (default 1). Use either this form or the single-key form, not both |
| `signer.roles.<role>.provider_revision` | Provider policy revision for this role; overrides `signer.provider_revision` |
| `tuf.root`, `tuf.trusted_root_keys`, `tuf.trusted_root_threshold` | Authenticated current TUF root and its independent trust inputs |
| `reviewer.key_id`, `public_key` | Release-evidence key used by `aos maintain release review` and, when present, by `aos maintain release fitness run` |
| `alert.program`, `alert.destination` | Alert delivery program and on-call destination; the section's digest is the `alert-config` fitness binding |

`predecessor_bundle`, `trusted_keys`, `[tuf]`, `[reviewer]`, and `[alert]`
may be omitted; a command that needs an omitted value refuses to run. The two
surfaces must have different identities.

Every `*_credential` key resolves to `$CREDENTIALS_DIRECTORY/<name>` or an
absolute path, is read without following links, and is trimmed. No secret
appears in the file itself.

#### Hub credentials

Every porcelain command that reaches a Hub surface (`new`, `advance`,
`publish`, and the steps they run) resolves that surface's token in this
order:

1. the surface's `token_credential`;
2. a non-empty `AOS_TOKEN`;
3. the renewable `aos hub login` profile stored for the surface origin,
   refreshed before use and before each object or multipart operation of a
   long upload.

The profile is resolved exactly as the `aos hub` commands resolve it, from
`$AOS_CONFIG_HOME/hub-profiles.json` (else `$XDG_CONFIG_HOME/aos/` or
`~/.config/aos/`), and only while it is the active profile.
`aos hub login --hub <origin>` makes its origin active, so when both surfaces
are Hubs without `token_credential`, sign in to a surface's origin before the
commands that reach it, or configure `token_credential` for one of them.
`AOS_TOKEN` is presented to every Hub surface that has no `token_credential`;
set it only when exactly one surface lacks one. A configured credential that
cannot be read fails the command; it never falls through to the next source.

Step commands run directly take `--token` or `AOS_TOKEN` first, then, with
`--config`, the configuration's `token_credential`, then the active login
profile. `status` and `explain` are offline and use no credential.

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
Follow [Bootstrap the first registry base](#bootstrap-the-first-registry-base)
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
`tooling` from the [release tooling environment](#release-tooling-environment),
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

## Step commands

`aos maintain release step` exposes the individual operations. Each takes explicit
inputs, verifies everything it consumes, and writes new outputs without
replacing an existing path. The porcelain constructs the same arguments from
the configuration and work directory.

| Command | Operation |
| --- | --- |
| `step contract` | Print the destination table, or one destination's profile and gates |
| `step plan` | Derive and freeze a plan from a request, Git, and the Nix inventory |
| `step build` | Realize and repeat-check every planned output |
| `step signer invoke` | Exercise one external signer exchange |
| `step finalize-image` | Sign and finalize one Linux image assembly |
| `step prepare-registry`, `step finalize-registry` | Author, review, and sign the isolated registry release |
| `step finalize-cache` | Generate and sign the static Nix cache |
| `step assemble`, `step finalize` | Close the payload and threshold-sign the bundle |
| `step verify` | Verify a captured bundle and journal offline |
| `step tuf` | Construct immutable TUF metadata |
| `step record` | Compose the public release record |
| `step compose-surface` | Compose registry, release, and TUF bytes for one destination |
| `step timestamp refresh`, `step timestamp publish` | Renew and publish TUF timestamp metadata |
| `step bootstrap` | Install the first registry base on an empty surface |
| `step publish` | Publish the bundle to one destination |
| `step qualification cases`, `step qualification execute`, `step qualification respond` | Inspect cases; run a configured scenario over exact public objects; bind a scenario report into an executor response |
| `step qualify-run` | Execute and sign one destination's qualification phase |
| `step channel advance`, `step channel complete` | Advance one rollout ring; close a destination's rollout |
| `step status` | Reconcile a captured journal, optionally against its plan |

The former `stage`, `promote`, and `qualify` commands no longer exist.
`step publish` performs both staging and production publication, and
qualification evidence is admitted by the publication and channel steps that
consume it.

### Prepare a plan request

`aos maintain release new` derives the request from the maintainer configuration and
live state. For a manual plan, create a reviewed JSON object with schema
`aos.release.plan-request/v1`. Unknown and duplicate fields are rejected. The
request supplies:

- release id, calendar version, and the release class derived from it;
- one registry authorized by [`registries.md`](registries.md) and its exact
  base commit and generation;
- protected source branch, unused immutable source tag, and SHA-256 digest of
  the public contributor-authorization summary;
- explicit decisions for both Linux system-image targets;
- signer roles and thresholds, the staging and production surfaces (kind,
  origin, optional read-back origin, and identity), the requested destinations
  with any override-accepted soak and rings, the change scope, references to
  accepted profile overrides, and retention policy;
- digests of the public evidence and restricted operator policies.

Package eligibility is deliberately absent from the request. Planning derives
every package decision from native recipe `platformSupport` declarations through
the caller-selected policy in [`pkgs/_target-policy.nix`](../../pkgs/_target-policy.nix).
The release contract selects this matrix:

| Artifact | `x86_64-linux` | `aarch64-linux` | `x86_64-darwin` | `aarch64-darwin` |
| --- | --- | --- | --- | --- |
| Packages | required cell | required cell | required cell | required cell |
| Images | required cell | required cell | not applicable | not applicable |

Each package cell is either a frozen set of exact derivation, named-output, and
store-path identities or an explicit inapplicable or blocked decision. A plan
with a destination whose profile requires a complete matrix (`soak`) rejects
blocked cells. Darwin receives packages only.

The contributor-authorization summary is a separate public file. Its exact
bytes must hash to the digest in the request. Do not place private employee or
agreement records in the source tree or release bundle.

The planner fills in each destination's profile, profile digest, gates, soak,
and rings from the contract. The requested destinations must equal the
contract's destinations for the registry tier, restricted to channels the
release class allows, and the surfaces must form a
[supported pair](#supported-surface-pairs).

### Generate the plan

Run planning from a clean source checkout on the designated maintainer host:

```sh
nix run . -- release step plan \
  --request release-request.json \
  --contributor-authorization contributor-authorization.json \
  --predecessor-manifest predecessor/bundle/release-manifest.json \
  --output release-plan.json
```

`--predecessor-manifest` names the predecessor's manifest payload or signed
envelope, from which planning computes the change scope; without it every
target is affected. To plan with a
[profile override](qualification.md#profile-overrides), add `--override DIR`
(repeatable) for each directory of signed envelopes and `--override-key
KEY_ID=PATH` for each release-evidence key that may approve them.

Releases require the checked-out commit to be the local protected branch head
and reachable from its protected local or remote reference. A plan that
references an accepted [profile override](qualification.md#profile-overrides)
may instead build a reviewed `dplecki/hotfix-*` branch whose head remains
reachable from the protected branch. The requested source tag must not exist,
unless it already names the planned commit: a main edge release and an experimental
edge release of the same version share one `release/<version>` tag on one
protected commit. A tag naming any other commit fails planning.

Planning is read-only except for the named output. It refuses a dirty checkout
and never replaces an existing output. The resulting file is canonical JSON;
its SHA-256 digest becomes the identity bound by every later operation. Preserve
both the reviewed request and generated plan as release evidence.

### Create a first qualification predecessor

When a registry has no prior signed release, create one retained, non-public
qualification snapshot from an earlier protected source revision and an older,
distinct calendar version. Its plan request uses the complete current contract
and normal package and image matrices, with exactly these reserved fields:

```json
{
  "release_id": "qualification-snapshot-2026.9.0-dev.20260904.0",
  "version": "2026.9.0-dev.20260904.0",
  "source": {
    "source_tag": "qualification-snapshot/2026.9.0-dev.20260904.0"
  },
  "destinations": []
}
```

The `qualification_predecessor` field is absent. The fragment shows the
relationship among the reserved values; retain all other required request
fields. Any other missing-predecessor shape fails planning, and the reserved
release id and source tag cannot be used by a plan that has a predecessor.

Snapshots are not driven by `aos maintain release new`. Run the ordinary `step plan`,
build, image-finalization, isolated-registry, cache, manifest, TUF,
timestamp-refresh, and surface-composition steps. Use the same release-evidence
and image authorities required by the contract. Do not run `bootstrap`,
`publish`, `qualify-run`, `record`, `timestamp publish`, or `channel`: those
steps reject qualification snapshots before any surface effect. The snapshot
does not claim that it passed an update from an earlier installation; its
purpose is to provide the first exact installed source for the candidate's
update and rollback cases.

Verify the final bundle offline with independently supplied manifest keys and
retain the JSON result:

```sh
aos --json release step verify qualification-snapshot/bundle \
  --journal qualification-snapshot/release-journal.jsonl \
  --trusted-key release-1=/media/trust/release-1.pub \
  --trusted-key release-2=/media/trust/release-2.pub \
  > qualification-snapshot-verification.json
```

The first public plan copies `verification.release_id` and
`verification.manifest_digest` into `qualification_predecessor` together with
the same registry identity. Preserve the closed snapshot bundle, journal,
verification output, public keys, and source tag. The Linux image executor must
verify that bundle again and exercise the exact snapshot-to-candidate transition;
a descriptor without the retained signed bytes is insufficient.

### Build the frozen package matrix

Record the UTC start time and select a new output directory. The command
captures the completion time after realization, repeat-building, and build
evidence collection finish:

```sh
nix run . -- release step build \
  --plan release-plan.json \
  --output release-build \
  --started-at 2026-09-03T10:00:00Z
```

The command realizes the exact named outputs from their frozen derivations and
then asks Nix to rebuild with `--check`. It refuses deriver or store-path drift
and records the exact NAR identity of every upstream source store path (internal
packages instead bind the protected repository source). It writes
`release-plan.json`, `evidence/build-report.json`,
`evidence/sbom.spdx.json`, and `release-journal.jsonl` without replacing an
existing path. A repeated build on one maintainer machine is nondeterminism
evidence, not an independent SLSA builder.

Inspect a copied journal without initializing Nix using
[`step status`](#inspect-a-captured-journal).

### Exercise an external signer

Signer provider selection and private-key resolution belong to deployment
configuration outside the repository. The executable path must be absolute,
single-linked, and not group- or world-writable. It receives a bounded binary
exchange on standard input under the fixed `sign-exchange-v1` operation: the
domain `aos.release.signer-exchange/v1` plus NUL, an unsigned big-endian request
length, canonical request JSON, an unsigned big-endian payload length, and the
exact public payload bytes. The response is framed with
`aos.release.signer-exchange-response/v1` plus NUL, a 64-bit response-JSON
length and canonical response, then a 64-bit transformed-output length and
those bytes. Detached operations set the final length to zero:

```sh
aos maintain release step signer invoke \
  --executable /opt/aos-signers/bin/provider-adapter \
  --request request.json \
  --payload payload.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --verification-identity device-slot-7 \
  --output response.json
```

The coordinator checks the request digest, role, operation, key id, provider
revision, public verification-material digest, and Ed25519 signature. It never
passes a private-key path to the provider.

#### File-backed signer for registries without an HSM

`aos-release-signer` (`nix build .#pkg-aos-release-signer`) implements the
exchange above for deployments whose private keys are operator-owned files,
which is the approved custody model for `andyl/experimental`. It reads a JSON
configuration named by `AOS_RELEASE_SIGNER_CONFIG` or `--config` that maps
each public key id to a private-key file, the roles it may serve, and the
verification identity the coordinator pins. The configuration, private keys,
and the wrapper that exports the environment variable live in restricted
deployment storage, never in the repository or the Nix store.

The adapter refuses any request whose provider revision or registry is not in
its configuration, whose key is not authorized for the requested role, or whose
payload does not reproduce the request digest. It signs Ed25519 request
digests and raw payloads in process, produces OpenSSH SSHSIG signatures for the
`registry` and `provenance` roles from an OpenSSH key whose roster trust line is
part of the configuration, signs measured-boot PCR policies and recovery
manifests with RSA, and delegates Authenticode and kernel-module signatures to
the `sbsign` and `openssl` executables named in its `tools` table. Its
`verification_material_digest` is always the SHA-256 of the configured public
file or trust line, so those bytes must be identical to the public copies the
image assembly and coordinator pin independently.

`aos-release-signer show` prints every configured key's public identity for
comparison with the public key inventory. `aos-release-signer sign-evidence
--key-id KEY --payload intent.json --output approval.json` wraps a canonical
approval payload, such as an `aos.release.registry-bootstrap-intent/v1`
document, in the `aos.hub.signed-release-evidence/v1` envelope that
`step bootstrap`, `step qualify-run --review-receipt`, `step channel
complete`, and profile overrides consume.

### Finalize each Linux image

Build the exact unsigned assembly named by the release plan, then invoke the
finalizer once for each Linux target. The signer adapter path and selected key
ids come from restricted deployment configuration; they are never stored in
the source repository or Nix output:

```sh
aos maintain release step finalize-image \
  --plan release-plan.json \
  --assembly /nix/store/…-aos-image-production-unsigned-assembly-2026.9.0 \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --signer-key secure-boot-db=db-2026 \
  --signer-key kernel-module=module-2026 \
  --signer-key pcr-policy=pcr-2026 \
  --work /var/lib/aos-release/2026.9.0/x86_64-linux
```

The work path must be absolute and must not exist. It is created with mode
`0700`. The command checks that the assembly store path is an exact artifact in
the matching plan image cell, captures all public inputs without following
links, and pins every executable to the current NAR hash of its owning AOS
store output. Each signer request binds the plan, role, provider revision,
public payload digest, and a fresh 256-bit nonce.

Successful output is under `WORK/finalized`. It contains canonical
`unsigned-image-assembly.json` and `finalized-image-set.json` control files plus
the artifact directory. Disk formats are accepted only after raw, QCOW2,
stream-optimized VMDK, and dynamic VHD independently reconstruct the same
logical GPT bytes. A failed operation leaves no `finalized` directory; retain
or remove the private work path according to the restricted operator policy.

Repeat for `x86_64-linux` and `aarch64-linux`. Darwin targets do not run this
command because their release matrix contains packages only.

### Prepare and finalize the isolated registry

Author the isolated registry once, before review. `prepare-registry` derives
every entry from the validated build report, obtains the planned provenance
signatures, validates the complete OCI layout and records its typed descriptor
graph with the exact finalized sidecar, regenerates and verifies
registry catalog TUF metadata over the current authored files, calculates all
registry surface digests, and writes the canonical
`aos.registry-release-transaction/v1` review file. It leaves the retained
registry clone uncommitted at the planned base ref.

```sh
aos maintain release step prepare-registry \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --container-release final-container/container-release.json \
  --container-signature-input final-container/signature-input.json \
  --container-layout final-container/layout \
  --source-registry /srv/aos-registry/authoring \
  --output /var/lib/aos-release/2026.9.0/registry \
  --transaction registry-transaction.json \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --provenance-key provenance-2026=/media/trust/provenance-2026.pub \
  --provenance-verification-identity provider-provenance-slot \
  --registry-key registry-2026=/media/trust/registry-2026.pub \
  --registry-verification-identity provider-registry-slot
```

Review the generated transaction and the retained registry diff together. Its
entries are strictly ordered by build artifact id, and its catalog,
store-graph, and policy digests bind the complete authored tree. Do not edit or
regenerate either input after review. Finalization revalidates the plan, build
report, OCI input, every entry, the store graph, base ref, and all three surface
digests before it requests either Git signature. Stale catalog metadata from
the base commit cannot be carried into a changed candidate or removed to bypass
verification.

Catalog TUF uses the active registry roster authority and the committed catalog
root's bootstrap and rotation rules. The source-built provider signs exact
catalog-alias/role/version-bound JSON through `CatalogTuf` requests in the
`aos-registry-tuf-v1` SSHSIG namespace. It does not use the distribution bundle's
separate TUF authorities or its payload digest domains. The outer request binds
the canonical Hub registry identity while the catalog context preserves the
local alias consumed by APM. APR's file-key producer
and this external provider path share metadata construction and verification;
preparation freezes the resulting `tuf/` bytes in the transaction policy digest.
The highest published root metadata version supplies rotation authority;
each role's floor is its maximum version across all published tags. A hotfix
on an older release line therefore continues metadata history even when its
source workspace starts from an older release.
The reviewed transaction also binds the optional complete container graph;
finalization evidence carries that graph into the stage inventory.

Each package/platform coordinate must contain exactly one `out` output. That
output remains the installable `store_path`; every additional named output is
retained in the platform entry's `named_outputs` table with its exact
`store_path`, native deployment companion when present, and output-specific
attestation facts. Each output receives its own store-graph and static-cache
root; NAR identities remain in the signed store graph. Preparation fails closed on a missing,
duplicate, or mismatched output binding.

```sh
aos maintain release step finalize-registry \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --transaction registry-transaction.json \
  --prepared-registry /var/lib/aos-release/2026.9.0/registry \
  --container-release final-container/container-release.json \
  --container-signature-input final-container/signature-input.json \
  --result /var/lib/aos-release/2026.9.0/registry-result.json \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --registry-key registry-2026=/media/trust/registry-2026.pub \
  --registry-verification-identity provider-registry-slot \
  --git-name "AOS Release" \
  --git-email release@aos.andyl.org \
  --git-unix-seconds 1788436800 \
  --git-offset-minutes 0
```

The generated transaction's optional `support` object states the `[support]`
tables this release writes into `registry.toml`: its own train's entry and,
only from the newest train, the rolling `default`. Both commands derive the
same object from the plan's frozen contract, and the policy digest describes
`registry.toml` after those tables are applied. A contract that names another
train's entry is rejected, so a backport release can only extend its own train.

Omit both container arguments from both commands for a release with no OCI
artifact; preparation removes any prior release's fixed-path sidecar from the
new tree. Supplying only one is invalid. The sidecar definition must be either
the compatibility alias `containerImages.aos` with exactly one planned image
variant, or the preferred
`systems.<planned-variant>.build.containers.aos` identity.

The two public key files contain exact
`<local-alias>:Ed25519:<base64>` trust lines: `andyl` for `andyl/main`, or the
epoch-matched `andyl-experimental` alias for `andyl/experimental`. Their key ids and
provider revisions must be the single-key,
threshold-one Provenance and Registry requirements frozen in the plan. The
single-signature DSSE and Git formats cannot honestly represent a larger
threshold, so the command rejects one rather than counting repeated signatures
outside the signed object.

During preparation, the provider signs the exact provenance DSSE PAE bytes in the
`aos-package-provenance-dsse-v1` SSHSIG namespace. For the commit and tag it
signs Git's exact unsigned object payload in the `git` namespace. The
coordinator verifies request binding, public-material identity, provider
identity, and the SSHSIG cryptographically before accepting each response. It
also checks the provenance trust line against the active, non-revoked
`keys.toml` entry before authoring.

The source registry must be clean at the exact plan base and must not already
contain the release tag. The output, transaction, and result paths must not
exist. Entry authoring may write catalog, documentation, provenance,
transparency, and store-graph files, but may not move a ref. Preparation
atomically installs the complete uncommitted directory. When any planned
destination's profile requires transaction review, `aos maintain release advance` stops
here until an operator accepts the transaction with `--accept-transaction`. Finalization operates
on those reviewed bytes, creates one signed commit and annotated tag, and
generates its static origin surface. Neither command modifies the authoring
ref, a surface object, a channel, or a private key path.

### Generate and sign the static cache

Generate the cache from the finalized isolated registry, not the mutable
authoring clone:

```sh
aos maintain release step finalize-cache \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --registry /var/lib/aos-release/2026.9.0/registry \
  --cache-key cache-2026=/media/trust/cache-2026.pub \
  --verification-identity provider-cache-slot \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --priority 40 \
  --jobs 8 \
  --output /var/lib/aos-release/2026.9.0/cache
```

The command checks that every built package-platform output appears at its
exact registry coordinate before reading the Nix store. It then expands the
complete registry closure, validates blessed store-graph membership, emits
deterministic compressed NARs and unsigned narinfos into a private temporary
directory, and asks the Cache role to sign each canonical Nix fingerprint.

Nix narinfo has a legacy raw `name:base64` Ed25519 signature field and cannot
embed the release request. The provider still receives the complete role,
release, plan, policy revision, payload digest, and fresh nonce; the coordinator
independently verifies the returned raw signature over the exact fingerprint
before appending it. The cache plan must therefore select exactly one cache key
with threshold one. The output becomes visible only after every narinfo is
signed, and existing output paths are never replaced.

### Close and sign the bundle

Before closing the bundle, prepare a reviewed canonical advisory disposition.
It binds the exact plan and SBOM, identifies each public advisory snapshot used
for review, and must contain no unresolved release blockers. The disposition
feeds the `build-integrity` observation that every profile requires, `build`
included, so a bundle with unresolved advisories cannot reach any destination,
staging or production:

```json
{"authority_id":"release-security-review","plan_digest":"sha256:...","reviewed_at":"2026-09-03T13:30:00Z","sbom_digest":"sha256:...","schema_version":"aos.release.advisory-disposition/v1","sources":[{"name":"osv","snapshot":"sha256:..."}],"unresolved_advisories":[]}
```

Run the assembler against the exact build, signed cache, finalized registry,
image, and container outputs:

```sh
aos maintain release step assemble \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --sbom release-build/evidence/sbom.spdx.json \
  --contributor-authorization contributor-authorization.json \
  --advisory-disposition advisory-disposition.json \
  --cache /var/lib/aos-release/2026.9.0/cache \
  --cache-key cache-2026=/media/trust/cache-2026.pub \
  --registry /var/lib/aos-release/2026.9.0/registry \
  --registry-result /var/lib/aos-release/2026.9.0/registry-result.json \
  --image-set /var/lib/aos-release/2026.9.0/x86_64-linux/finalized \
  --image-set /var/lib/aos-release/2026.9.0/aarch64-linux/finalized \
  --container final-container \
  --completed-at 2026-09-03T14:00:00Z \
  --output release-assembled
```

Omit `--container` only when the qualification contract has no applicable
container target. The command verifies every narinfo signature, compressed-file
identity, decompressed NAR hash, and complete reference closure. It copies a
distinct NAR for every planned logical artifact id, verifies registry
finalization identities, checks finalized image sets and the complete OCI graph
against the exact sidecar committed into that registry, and derives the exact
build-phase qualification observation. It emits
`release-assembled/payload/` and
`release-assembled/release-manifest-payload.json` atomically without replacing
an existing path.

The payload includes package NARs, signed narinfos, registry objects,
provenance, source and license material, the SBOM, build evidence, and finalized
Linux image and OCI artifacts. It does not contain `release-plan.json` or
`release-manifest.json`; the finalizer installs the exact plan itself. Links,
aliases, special files, incomplete closures, unresolved advisories, and bytes
that differ from a finalized input stop assembly.

The registry's finalized `HEAD` names the new release commit, but every
publication must keep discovery on the planned base commit until a channel
operation moves it; the compare-and-swap checks require the published default
commit to equal `registry_base_commit`. The assembler therefore retains the
finalized author's `HEAD` as evidence at `evidence/registry-head` and places a
`registry/HEAD` object (`registry/publication-head`) naming the base commit,
which the publication projects to the surface's `HEAD`. Source-inclusive caches
may carry derivation (`.drv`) store paths, and store-path names follow Nix's own
character rules, including the `?` and `=` that fetched source names retain.

Every `package-nar` record must point to its exact signed `narinfo` record with
an `authenticated-by` relationship. Its outbound relationship graph also names
the dependency NARs and their narinfos needed for public closure verification;
qualification downloads that complete transitive graph from the staging
surface's public read-back route.

```sh
aos maintain release step finalize \
  --plan release-plan.json \
  --payload release-assembled/payload \
  --manifest-payload release-assembled/release-manifest-payload.json \
  --journal release-build/release-journal.jsonl \
  --signing-key release-1=/media/trust/release-1.pub \
  --signing-key release-2=/media/trust/release-2.pub \
  --verification-identity release-1=provider-release-slot-1 \
  --verification-identity release-2=provider-release-slot-2 \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --recorded-at 2026-09-03T14:00:00Z \
  --output /var/lib/aos-release/2026.9.0/finalized
```

Supply exactly the key count required by the plan's ReleaseEvidence threshold,
with one independently pinned provider identity for each key. The command
captures source files through no-follow handles, copies and hashes them in one
pass, rechecks file metadata and directory membership, and compares every byte
count and SHA-256 value to the manifest. It then asks each external signer to
authorize the exact canonical manifest payload, verifies every response, writes
the signed envelope, and runs the ordinary offline verifier over the completed
tree before making the result visible.

The new output contains `bundle/` and `release-journal.jsonl`. The journal is a
strict successor of the supplied Built journal and binds the manifest digest,
provider operation ids, and signature-response evidence. Neither output path is
reused or replaced.

TUF repository metadata is deliberately not a manifest target. Its delegated
release entry authorizes the finalized manifest envelope, whose artifact list
already closes every bundle payload. Keeping root, targets, delegated targets,
snapshot, and timestamp on the registry metadata surface avoids an impossible
self-reference in which a manifest inventories TUF bytes that themselves name
the manifest or whole-bundle digest. Publication receipts continue to bind the
separate exact-byte bundle digest.

### Verify a captured bundle offline

Copy the closed bundle, optional journal, and public verification keys to a
machine that does not need Nix, Git, registry, surface, or network access. Then run:

```sh
aos maintain release step verify ./release-bundle \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --journal ./release-journal.jsonl
```

Repeat `--trusted-key KEY_ID=PATH` to satisfy the manifest threshold. The
verifier rejects links, special files, hard-linked artifacts, path escapes,
non-canonical control documents, digest or size mismatches, invalid signatures,
incomplete matrices, and invalid journal transitions, including a destination
published before its `after` prerequisite. It streams artifact
digests, so disk images need not fit in memory.

Use public keys from an independently authenticated source. A key shipped only
inside the bundle it is meant to authenticate is not a trust anchor.

### Construct immutable TUF metadata

Use an independently authenticated, already signed production root. When the
root is a rotation, also supply its predecessor so both old-root and new-root
thresholds are checked. Build the immutable per-release metadata only after the
bundle manifest is final. Each surface keeps its own TUF metadata versions,
so the driver runs this step for the first destination it publishes on each
surface, after `step record` on the production surface:

```sh
aos maintain release step tuf \
  --plan release-plan.json \
  --bundle finalized/bundle \
  --manifest-key release-1=/media/trust/release-1.pub \
  --manifest-key release-2=/media/trust/release-2.pub \
  --root 12.root.json \
  --trusted-root-key root-1=/media/trust/root-1.pub \
  --trusted-root-key root-2=/media/trust/root-2.pub \
  --trusted-root-threshold 2 \
  --targets-key targets-1=/media/trust/targets-1.pub \
  --delegated-key stable-1=/media/trust/stable-1.pub \
  --delegated-key stable-2=/media/trust/stable-2.pub \
  --snapshot-key snapshot-1=/media/trust/snapshot-1.pub \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --targets-version 43 \
  --delegated-version 19 \
  --snapshot-version 44 \
  --targets-expires 2027-09-03T00:00:00Z \
  --delegated-expires 2027-09-03T00:00:00Z \
  --snapshot-expires 2026-12-03T00:00:00Z \
  --now 2026-09-03T14:30:00Z \
  --output finalized-tuf
```

The command requires TUF root, targets, snapshot, timestamp, and the selected
release-class role in every release plan. It verifies that plan key ids and
thresholds exactly equal the trusted root policy, that each supplied public key
matches the root bytes, and that provider revisions come from the frozen plan.
Every signer request binds the plan, final manifest, metadata role and version,
payload digest, operator-policy digest, and a fresh nonce. The complete set is
verified again through the independently supplied root trust before a
no-replace atomic rename makes it visible.

The delegated target names the exact signed `release-manifest.json` envelope by
SHA-256 and byte length. The snapshot names exact versioned root, targets, and
delegated envelopes. Do not copy these files into a publication tree manually;
the surface-composition command below verifies and installs them.

### Compose the public release record

After the staging-phase report for a production destination is signed, derive
the public release record from the exact evidence that destination's
publication consumes. Every field is copied from the frozen plan, the final
manifest, the signed qualification, and the public report after the same
verification `step publish` performs; nothing is authored.

```sh
aos maintain release step record \
  --to production/candidate \
  --bundle release-final \
  --staging-receipt release-staging-candidate/receipt.json \
  --signed-qualification qualification-candidate-staging/signed-qualification.json \
  --qualification-report qualification-candidate-staging/qualification-report.json \
  --trusted-key manifest-2026=/media/trust/manifest-2026.pub \
  --qualification-key qualification-authority=/media/trust/qualification.pub \
  --output release-record-candidate.json
```

The record (`aos.release-record/v1`) states the release identity and train,
the qualification result, policy, authority, and signing time, every claim
with its required and achieved assurance, the train's support statement from
the plan's contract, provenance digests, and the exact signed qualification
envelope. Pass it to `step tuf --release-record` so the delegated role
authorizes it beside the manifest, and to `step compose-surface
--release-record` so it is served at
`releases/<class>/<version>/release-record.json`. Composition fails closed when
the delegated targets and the supplied record disagree in either direction.
Consumers verify the record through the TUF chain and, independently, through
its embedded signed envelope; a Hub surface renders it only after verifying
that envelope against its trusted qualification keys. Staging destinations
carry no record. A surface serves one record per release: the record composed
for the first production destination published there. A later destination on
the same surface reuses that publication and attaches its own signed
qualification to its journal entry.

### Refresh TUF timestamp metadata

Timestamp renewal cannot add release content or replace a snapshot. Supply the
current signed root and snapshot, independently authenticated root keys, and
exactly the timestamp-role signature threshold:

```sh
aos maintain release step timestamp refresh \
  --to production/stable \
  --plan release-plan.json \
  --root 12.root.json \
  --snapshot 41.snapshot.json \
  --previous-timestamp timestamp.json \
  --trusted-root-key root-1=/media/trust/root-1.pub \
  --trusted-root-key root-2=/media/trust/root-2.pub \
  --trusted-root-threshold 2 \
  --signing-key timestamp-1=/media/trust/timestamp-1.pub \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --version 87 \
  --issued-at 2026-09-03T12:00:00Z \
  --expires 2026-09-05T12:00:00Z \
  --output timestamp.json.next
```

The command verifies the root bootstrap threshold, production role separation,
snapshot signature, root/plan timestamp policy equality, signer public key and
provider identity, prior timestamp continuity, and the 48-hour maximum window.
Continuity has three cases:

| Prior timestamp | Snapshot supplied | New timestamp |
| --- | --- | --- |
| None: the surface has never served one | Any authorized snapshot | Version 1 |
| Names the same snapshot | The same snapshot | Version N+1 over that snapshot (renewal) |
| Names an older snapshot | A newer authorized snapshot | Version N+1 over the newer snapshot (a new release on the surface) |

`--version` must be exactly the prior version plus one, and a new snapshot's
version must be greater than the snapshot the prior timestamp names. Any other
combination fails closed. An expired prior timestamp remains cryptographically
verifiable at its recorded issuance instant, so freshness can recover without
resetting the monotonic version. The porcelain uses the new-snapshot case for
every release after the first on a surface; the renewal timer uses the renewal
case. Publish the resulting pointer through the destination surface's
compare-and-swap operation. First atomically compose it with the immutable
registry/cache surface, full verified TUF set, and exact delegated manifest
target:

```sh
aos maintain release step compose-surface \
  --to production/stable \
  --plan release-plan.json \
  --bundle finalized/bundle \
  --manifest-key release-1=/media/trust/release-1.pub \
  --manifest-key release-2=/media/trust/release-2.pub \
  --base-surface finalized-registry-surface \
  --root finalized-tuf/12.root.json \
  --targets finalized-tuf/43.targets.json \
  --delegated finalized-tuf/19.stable.json \
  --snapshot finalized-tuf/44.snapshot.json \
  --timestamp timestamp.json.next \
  --previous-timestamp-version 86 \
  --trusted-root-key root-1=/media/trust/root-1.pub \
  --trusted-root-key root-2=/media/trust/root-2.pub \
  --trusted-root-threshold 2 \
  --now 2026-09-03T12:05:00Z \
  --output complete-registry-surface
```

Composition captures the base tree without following links, rejects aliases
and special files, verifies the signed bundle and complete TUF chain, installs
the exact manifest envelope at its delegated release path, retains identical
historical immutable metadata, replaces the timestamp only inside a private
temporary tree, fsyncs the result, and exposes it with a no-replace atomic
rename. Then publish that closed surface:

```sh
aos maintain release step timestamp publish \
  --to production/stable \
  --plan release-plan.json \
  --root 12.root.json \
  --snapshot 41.snapshot.json \
  --timestamp timestamp.json.next \
  --previous-version 86 \
  --trusted-root-key root-1=/media/trust/root-1.pub \
  --trusted-root-key root-2=/media/trust/root-2.pub \
  --trusted-root-threshold 2 \
  --registry-surface complete-registry-surface \
  --output timestamp-publication-87
```

The complete surface must contain the exact verified envelopes at
`tuf/timestamp.json` and `tuf/41.snapshot.json`. On a Hub surface the
coordinator uploads the surface into an invisible preparing publication, and
the release-scoped Hub RPC atomically reserves the next timestamp version and
exact object identities before it commits the mutable publication pointer. A
lost response is retried with the same publication and evidence; a different
request for the reserved version fails closed. On a static surface the
coordinator replaces `tuf/timestamp.json` with the surface's
[compare-and-swap](#static-surfaces). The coordinator then performs full anonymous public
read-back and preserves the timestamp plus publication evidence without
replacing an existing output.

### Bootstrap the first registry base

A new staging or production surface has no publication that can serve as the
compare-and-swap parent of its first release. Do not let the first release
self-authorize that base. Obtain identical
`aos.release.registry-bootstrap-intent/v1` envelopes signed by exactly the
plan's `release-evidence` threshold. The intent binds the environment,
surface identity, the plan's exact registry identity, planned base commit, plan
digest, public authority, and approval time.

A registry's first release runs in this order:

1. Create the registry on each surface without publishing anything: the
   reviewed `aos hub registry create` plan and apply on a Hub, or the
   `.aos-surface` identity on a static origin.
2. Plan with
   [`new --first-release --source-registry`](#plan-a-registrys-first-release).
   Note the printed plan digest and the base commit in the `Registry` row.
3. Write one intent payload per environment. Every approver signs the same
   bytes, so `authority_id` names the approving authority rather than one key,
   and `approved_at` is fixed before signing:

   ```json
   {
     "schema_version": "aos.release.registry-bootstrap-intent/v1",
     "environment": "staging",
     "deployment_id": "staging-2026-09",
     "registry": "andyl/experimental",
     "base_commit": "<registry_base_commit from plan.json>",
     "plan_digest": "sha256:<SHA-256 of plan.json>",
     "authority_id": "andyl-release-evidence",
     "approved_at": "2026-10-02T12:00:00Z"
   }
   ```

   Each release-evidence key holder signs it, for example with
   `aos-release-signer sign-evidence --key-id release-evidence-v1
   --payload staging-intent.json --output approvals/staging-bootstrap-1.json`.
4. Export the clone's root commit as a static registry surface:
   `apr origin upload --registry andyl-experimental --upload-url
   file:///var/lib/aos-release-coordinator/base-registry-surface`.
5. Run `step bootstrap` for staging, then for production, as below.
6. Place the clean clone at `<work>/inputs/source-registry/` and continue
   with `aos maintain release advance --to staging/<channel>`.

Install the reviewed base in staging first:

```sh
aos maintain release step bootstrap \
  --plan "$WORK/plan.json" \
  --registry-surface base-registry-surface \
  --environment staging \
  --signed-intent approvals/staging-bootstrap-1.json \
  --signed-intent approvals/staging-bootstrap-2.json \
  --approval-key evidence-1=/media/keys/evidence-1.pub \
  --approval-key evidence-2=/media/keys/evidence-2.pub \
  --config /etc/aos-release/maintainer.toml \
  --output "$WORK/bootstrap/staging"
```

Repeat with independent production intent envelopes, the production
credentials, `--environment production`, and
`--output "$WORK/bootstrap/production"`. `advance` reads exactly these output
directories: it refuses one that lacks `bootstrap-evidence.json` or records
another environment or base commit. A Hub surface takes `--token` or
`AOS_TOKEN`, else, with `--config`, the configuration's `token_credential`,
else the active `aos hub login` profile for its origin
([Hub credentials](#hub-credentials)); a static surface's upload credentials
come from the maintainer configuration named by `--config`.
The command dispatches on the plan's surface kind: it uses the Hub publication
protocol for a Hub surface and writes the base surface, with its registry head
object, directly to a static origin whose `.aos-surface` already names the
planned identity. The command
refuses a destination containing any publication, requires the resulting first
publication to have no parent, checks its default commit against the plan,
pins the surface identity before and after upload, and performs
complete and ranged public read-back. Preserve the emitted bootstrap evidence;
all later release publications use this base publication as their explicit
parent. Bootstrap is not a recurring release step.

### Publish to a destination

`step publish` places the exact finalized bundle on one destination's surface.
It dispatches on the plan's surface kind: the Hub publication protocol for a
`hub` surface, direct upload for a [static surface](#static-surfaces). Staging:

```sh
aos maintain release step publish \
  --to staging/candidate \
  --bundle release-bundle \
  --journal release-bundle/release-journal.jsonl \
  --surface staging-candidate-surface \
  --trusted-root-key root-2026=/media/keys/root-2026.pub \
  --trusted-root-threshold 1 \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --output release-staging-candidate
```

Production additionally requires the staging receipt, the destination's signed
staging-phase qualification, and the fitness attestations its profile names:

```sh
aos maintain release step publish \
  --to production/candidate \
  --bundle release-bundle \
  --journal release-staging-candidate/release-journal.jsonl \
  --surface production-candidate-surface \
  --trusted-root-key root-2026=/media/keys/root-2026.pub \
  --trusted-root-threshold 1 \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --predecessor-receipt release-staging-candidate/receipt.json \
  --predecessor-receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --evidence qualification-candidate-staging \
  --qualification-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --fitness /var/lib/aos-release-coordinator/fitness \
  --output release-production-candidate
```

A staging destination's `build` profile requires no qualification evidence,
predecessor receipt, review, or fitness attestation: `step publish --to
staging/<channel>` rejects `--evidence` and `--predecessor-receipt`. Everything
else still applies. The build's repeat-build and deriver checks, the
advisory disposition, and the `build-integrity` observations are required for
every destination, and every publication, staging included, is read back
anonymously in full.

`--surface` is the destination's composed surface from [`step
compose-surface`](#refresh-tuf-timestamp-metadata), which carries the TUF
metadata and, for a production destination, the release record. It requires
the independently trusted `--trusted-root-key KEY_ID=PATH` values and their
`--trusted-root-threshold` (default 2). Before anything is uploaded, the
surface's snapshot (or its timestamp, when present), root, targets, and
release-class delegation must keep the plan's frozen signer policy and verify
against those root keys, and the delegated target must bind this bundle's
manifest envelope. The published surface is then exactly the projected bundle
plus those verified additions: the TUF metadata files, the public manifest
(identical to the bundle's envelope), and the release record only when the
delegated target authorizes its exact digest and length. Any other composed
file must be byte-identical to the projected object at its path; an extra,
changed, or missing verified file fails the command. Fitness is
checked against the attestations under `--fitness DIR` and the live binding
values given by `--tooling-digest`, `--alert-config-digest`, and
`--hub-schema`. Explicit flags win; otherwise the maintainer configuration
named by `--config` supplies `fitness_root` and the live values, which is how
the porcelain calls the command. A Hub surface takes a short-lived token for
that surface only, through `--token` or `AOS_TOKEN`, or the configuration's
`token_credential`; without either, it uses the approved `aos hub` login
profile for that origin, whose credentials are refreshed before each object or
multipart operation of a long upload. An explicit token's lifetime remains the
caller's responsibility. A static surface resolves
its upload credentials and the `surface-receipt` signer from the maintainer
configuration named by `--config`, with the same default search as the
porcelain. Keep staging and production credentials in different operator steps.

Before any upload, the command verifies the complete bundle, signature
threshold, and journal: the release must be `finalized` and every surface role
in the destination's `after` list must already be published. For a production
destination it verifies the staging receipt, the signed qualification against
its independent key, that the qualification covers exactly the destination's
planned gates under the recomputed change scope, that every required review is
present, and that every required fitness attestation is fresh and matches the
live bindings.

The command checks the surface identity before and after upload, reads every
committed object back anonymously through the public read-back route, and
compares its exact SHA-256 and size, including exact prefix and suffix byte
ranges where the origin is HTTP. The receipt is verified with an independently
pinned surface receipt key rather than a release-manifest key. On a production
Hub, the surface also verifies and imports the signed staging and
qualification envelopes and binds them to its publication. A surface that
already holds this release's publication for another destination is verified
by full read-back instead of a second upload.

The output contains the destination's `receipt.json` and a successor
`release-journal.jsonl` with a `published` entry for the destination. A
production entry carries the digests of the admitted qualification evidence;
there is no separate qualified state. Existing paths are never replaced.

### Run the native qualification matrix

Configure absolute executable paths for the applicable platforms. The Linux paths invoke Linux
test closures. The Darwin paths are credential-free authenticated remote
adapters whose far ends execute on supported Intel and Apple Silicon macOS.
Release-wide cases use the x86_64 Linux executor. Image and container cases
select their declared reference target; package cases select each published
package/platform independently. An absent unrelated platform requires no
adapter. The destination's profile and the plan's change scope select the
cases.

Each adapter reads one canonical request from standard input and writes one
canonical `aos.release.qualification-executor-response/v1` object to standard
output. Successful adapters must not write diagnostics. They download every
object they exercise from the anonymous URLs in the request and verify the
declared length and SHA-256 before testing it. Image update requests also
carry a separate inventory of exact objects from the locally retained,
offline-verified predecessor bundle. The executor recaptures those files into
its private attempt directory and checks their lengths and hashes before the
image scenario can use them.

Run `aos maintain release step qualification cases --to <destination>` first and retain its
`environment_profile_digests`. Review the compatibility scope and sources for
each required target, then install the canonical assessment object as
`/etc/aos-release/qualification-assessments/<target-id>.json` on the applicable
Linux executor host. The built-in container lifecycle program refuses a
missing, symlinked, or scope-mismatched assessment and records its own concrete
execution inventory. Run the `release-tooling` closure that ships the
matching executor rather than copying an individual scenario script without
its closure.

```sh
aos maintain release step qualify-run \
  --to production/candidate \
  --phase staging \
  --bundle release-bundle \
  --staging-receipt release-staging-candidate/receipt.json \
  --predecessor-bundle /srv/aos-release/qualification-snapshot/bundle \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --hub-receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --executor x86_64-linux=/run/aos-release/executors/x86_64-linux \
  --executor aarch64-linux=/run/aos-release/executors/aarch64-linux \
  --executor x86_64-darwin=/run/aos-release/executors/x86_64-darwin \
  --executor aarch64-darwin=/run/aos-release/executors/aarch64-darwin \
  --executor-identity x86_64-linux=linux-x86-v1 \
  --executor-identity aarch64-linux=linux-arm-v1 \
  --executor-identity x86_64-darwin=macos-intel-v1 \
  --executor-identity aarch64-darwin=macos-apple-silicon-v1 \
  --authority-executable /run/aos-release/signers/qualification \
  --authority-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --authority-verification-identity qualification-provider-v1 \
  --executor-nonce 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --authority-nonce abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
  --qualified-at now \
  --prepare-only \
  --output qualification-prepared
```

Both nonce values are single-use operator inputs. The plan must name a distinct
`qualification` signer role with exactly the public key supplied above. The
predecessor bundle path must be absolute. `qualify-run` verifies its complete
signed closure against `--trusted-key` and the plan's exact predecessor
registry, release ID, and manifest digest before starting any executor. Supply
it while collecting observations; omit it when admitting a reviewed report
with `--report-input`. The collection command retains each machine-readable
executor report and the canonical aggregate report. Review those exact bytes,
then repeat the command with
`--report-input qualification-prepared/qualification-report.json`,
`--review-receipt approvals/review.json`, and `--output qualification`, omitting
`--prepare-only`. Repeat review receipts to satisfy the destination's review
threshold. The staging phase always reads the staging surface; rollout and
complete phases read the destination's surface through
`--publication-receipt`, the alias of `--staging-receipt`, with that surface's
receipt key in `--hub-receipt-key`. A rollout run adds `--ring N`,
`--prior-generation G`, and `--journal`; a complete run adds `--journal`.
The [shared qualification guide](qualification.md#collect-review-and-sign)
specifies the review payload and later hold points. Missing applicable adapters
fail closed. `--qualified-at now` resolves after collection, avoiding a receipt
time earlier than the tests it authorizes.

### Advance a planned channel ring

Advance only a ring frozen in the plan's destination, using the exact
generation observed by the operator. Rings are numbered from 1 in profile
order; ring `N` covers the partitions after ring `N-1`'s cumulative count up to
its own. When the profile has a rollout gate, first collect and sign a
`rollout` report for that ring against the destination's publication receipt
and current journal, as specified in
[the shared guide](qualification.md#collect-review-and-sign):

```sh
aos maintain release step channel advance \
  --to production/stable \
  --ring 2 \
  --prior-generation 7 \
  --qualification qualification-stable-rollout-2 \
  --qualification-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --bundle release-bundle \
  --journal release-stable-ring-1/release-journal.jsonl \
  --publication-receipt release-production-stable/receipt.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --channel-receipt-key channel-2026=/media/keys/channel-2026.pub \
  --output release-stable-ring-2
```

Omit `--qualification` and `--qualification-key` for a destination whose
profile has no rollout gate (`build` and `smoke`). Pass each earlier ring's
channel receipt of the destination with a repeated `--channel-receipt`. On a
static surface `--prior-generation` may be omitted, and the command reads the
current generation record instead. The command takes the same fitness inputs
as `step publish`, plus `--token` for a Hub surface or `--config` for a static
one. It works for staging and production destinations and for both surface
kinds. The previous ring's `observe_seconds` must have elapsed since its
channel receipt. On a destination whose profile selects no `qualified` claims,
the final ring's advance also records the destination `complete`.

On a Hub surface the Hub commits the generation evidence, channel frontier, and
every selected partition in one transaction; a staging Hub accepts the advance
once it holds the release's staging publication, and a production Hub requires
its production publication. The channel must already exist on the Hub as an
indexed channel; see [channels and receipts](#channels-and-receipts). On a
static surface the command performs the [compare-and-swap](#static-surfaces)
itself. A stale generation, missing publication, altered public projection,
stale health approval, or ring outside the plan fails closed. The command
verifies the publication receipt through the anonymous route before mutation,
verifies the signed channel receipt afterward, reads every selected public
partition back, and appends a `rolling` journal entry for the destination.
Later rings append `rolling`-to-`rolling` entries with their own generations
and receipts. For a `soak` destination, closing the rollout is a separate
retention and handoff decision.

### Complete a rollout

After every planned ring has advanced, obtain identical completion decisions
signed by exactly the `release-evidence` threshold frozen in the plan. Each
canonical decision uses schema `aos.release.completion-receipt/v1` and binds the
release, plan, manifest, the destination's publication receipt, the sorted
digest of every channel receipt, the exact rolling journal-head digest, the
frozen retention policy, affirmative corresponding-source retention,
affirmative operational handoff, a public authority identity, and an RFC 3339
UTC completion time. `aos maintain release review` produces one such decision per
reviewer.

When the destination's profile has a complete gate (`soak`), collect and sign
the `complete` observation report after the soak, using the publication receipt
and current rolling journal. Then recheck the complete public rollout and close
the destination:

```sh
aos maintain release step channel complete \
  --to production/stable \
  --qualification qualification-stable-complete \
  --qualification-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --bundle release-bundle \
  --journal release-stable-ring-4/release-journal.jsonl \
  --publication-receipt release-production-stable/receipt.json \
  --channel-receipt release-stable-ring-1/channel-receipt.json \
  --channel-receipt release-stable-ring-2/channel-receipt.json \
  --channel-receipt release-stable-ring-3/channel-receipt.json \
  --channel-receipt release-stable-ring-4/channel-receipt.json \
  --completion-receipt approvals/completion-release-evidence-1.json \
  --completion-receipt approvals/completion-release-evidence-2.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --channel-receipt-key channel-2026=/media/keys/channel-2026.pub \
  --completion-key evidence-1=/media/keys/evidence-1.pub \
  --completion-key evidence-2=/media/keys/evidence-2.pub \
  --output release-stable-complete
```

Only a destination whose profile selects `qualified` claims (`soak`) runs
this command; every other destination is already `complete` after its final
ring. The
command accepts no access token and performs no surface mutation. It verifies
one signed channel receipt for every planned ring, proves each receipt is
already part of the rolling journal, rejects gaps in the destination's
generations, checks the anonymous publication receipt and all public
partitions, and verifies that every completion signer approved identical
bytes. The output retains all receipts and appends the destination's sole
`rolling`-to-`complete` transition without replacing an existing path.

### Inspect a captured journal

Inspect any copied journal without initializing Nix or reaching a surface:

```sh
aos maintain release step status --journal release-stable-complete/release-journal.jsonl --plan plan.json
```

The command verifies the hash chain and every transition, then prints the
global state and each destination's state. With `--plan`, it also lists the
planned destinations that are not yet published.

## Static surfaces

A static surface is a publication endpoint that is not an AOS Hub. It is a
directory tree served by an ordinary origin, written directly by the
coordinator and read back anonymously. Nothing on the static path calls a Hub,
and a registry whose surfaces are both static needs no Hub deployment at all.

| Origin scheme | Upload | Read-back | Compare-and-swap |
| --- | --- | --- | --- |
| `file://` | Direct filesystem writes | The same path, or an `https://` read-back origin | Exclusive `create_new` lock file plus temporary-file rename |
| `s3://bucket/prefix` | S3 API with the AWS default credential chain and the surface's `s3_region`, `s3_profile`, and `s3_endpoint` | `readback_origin`, required | `If-Match` and `If-None-Match` conditional writes against the returned ETag |
| `sftp://host/path` | SFTP with a configured credential | `readback_origin`, required | Temporary write, rename, and exclusive-create lock |
| `https://` | Not supported | Accepted only as a `readback_origin` | Not applicable |

### Supported surface pairs

| Staging | Production | Accepted |
| --- | --- | --- |
| Hub | Hub | Yes |
| Hub | Static | Yes |
| Static | Static | Yes |
| Static | Hub | No: a production Hub cannot yet verify receipts from a static staging surface |

Planning rejects the unsupported pair and requires the two surfaces to have
different identities.

### Surface identity

The file `.aos-surface` at the read-back root contains the surface identity
string, and it must equal the plan's surface `identity`. `new` reads it when
freezing the plan; `publish`, `channel advance`, and `timestamp publish` read it
before and after every mutation. Provision it once when creating the surface
and never reuse an identity for a different origin. A new identity is a new
surface: its `hub-restore` and `key-rotation` fitness attestations must be
recorded again.

### Layout

`step publish` projects the captured bundle into the machine surface layout,
driven by the manifest's artifact records rather than path prefixes:

| Bundle path | Surface path |
| --- | --- |
| `registry/<path>` | `<path>` |
| `cache/nix-cache-info` | `nix-cache-info` |
| `cache/narinfo/<hash>.narinfo` | `<hash>.narinfo` |
| `cache/nar/...` | `nar/...` |
| Image, container, evidence, closure, and source artifacts | `releases/<role>/<version>/...` at each artifact's declared public path |
| Signed manifest envelope | `releases/<role>/<version>/release-manifest.json` |

`<role>` is the release's TUF delegated role (`edge`, `candidate`, or
`stable`). The composed surface also carries `tuf/`, where `tuf/timestamp.json`
is the only mutable object and every versioned metadata file is immutable, and
the release record beside the manifest for production destinations. Channel
state lives under `channels/<name>/`: one object per partition
(`channels/<name>/00` through `channels/<name>/ff`) and the generation record
`channels/<name>/generation` (`aos.release.channel-generation/v1`).

Immutable objects are uploaded before mutable ones. The command then reads
every object back from the read-back origin, compares its digest and size, and
exercises range requests where the origin is HTTP.

### Channels and receipts

A channel advance on a static surface reads the current generation record,
takes the scheme's lock or conditional write, writes the ring's partition
objects and the successor generation record, uploads, and reads both back. A
generation that changed since the operator observed it fails closed without
writing partitions. Partition objects are signed by the plan's `registry` role
using the Git tag signing context; the signer request binds the destination,
ring, and partition range.

Publication and channel receipts have one shape on every surface:
`aos.release.publication-receipt/v1` and `aos.release.channel-receipt/v1`
documents naming the surface kind, surface identity, destination, and the
predecessor receipt they follow; channel receipts also name the ring. A static
surface signs them locally with the plan's `surface-receipt` role, which Hub
surfaces never use. A Hub deployment issues the same documents signed by its
own receipt keys, and the coordinator records both kinds verbatim.

TUF timestamp publication on a static surface replaces `tuf/timestamp.json`
with the same compare-and-swap and read-back.

A static surface creates a channel's `channels/<name>/` objects on its first
advance. A Hub surface does not: every channel, including a per-train channel
such as `stable-2026.9`, must already exist as an indexed row in the Hub's
`channels` table before `step channel advance` succeeds. The Hub indexes
channels from the registry publications it serves, so a new per-train channel
must appear in an indexed publication on that deployment before its first
advance; otherwise the advance fails closed.

## Exercise the complete Hub transition in a fleet

Native Hub deployments terminate TLS in `aos-hub` itself. Configure
`aos.registry-hub.listen` for the public listener, set an HTTPS `externalUrl`,
and supply the `tlsCertificate` and `tlsPrivateKey` credential names. The
listener rejects missing or unexpected SNI and injects HTTPS route evidence
only after a successful rustls handshake; the Hub does not infer security from
forgeable forwarding headers. Keep the private key in the deployment secret
provider and rotate it by replacing the systemd credential followed by a
service restart.

`checks.fleet.native-hub-release-pipeline` is the production-shaped acceptance
test for the online half of this runbook. It boots separate native staging and
production Hub machines with distinct deployment identities, publication keys,
and channel keys using native TLS at the canonical hostnames. The Hub system module
loads every private signing seed and trust map through systemd credentials; a
partial release-evidence configuration fails evaluation.

The publisher is the only machine with `hostStoreMount = true`. It mounts the
host Nix store read-only through the fleet 9p device, binds and registers only
four small prebuilt fixture closures, and exports one NAR for each package cell:
`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`. Those
payloads are not rebuilt into any guest image. Darwin participates only in the
package and qualification matrix; no Darwin image cell is created.

The test initializes both empty native Hubs and creates the public
`andyl/main` delivery topology through reviewed `aos hub` operations, without
any publication. The release is therefore the registry's first: the publisher
approves a real `aos hub login` device ceremony for staging and configures
production with `token_credential`, shows that `new` refuses the
unbootstrapped staging surface without `--first-release` and refuses a dirty
authoring clone, and derives the request with
`new --first-release --source-registry --request-only` from the single-commit
clone `apr create` wrote. The fixture then stands in for the Nix-evaluated
`step plan` leaf, which needs an AOS source checkout the fleet does not carry:
it freezes the request's base, generation, surfaces, and destinations into a
plan around the four prebuilt package cells. Threshold-signed intents install
that base with `step bootstrap` on staging (through the login profile) and
then production, a second bootstrap and a second first-release plan are
refused, and the real step commands perform offline verification, staging
publication, four-platform public-byte qualification, production
publication with qualification admission, channel compare-and-swap, and
rollout completion. It verifies the final journal state and anonymous
production channel object. The deterministic authorities and TLS
key used by this test are confined to explicit test fixtures and the
`pkgs.aos.testSupport` output; no test authority is installed in a shipped CLI
output.

Run the focused evaluation and fleet gate with:

```sh
nix-build -A checks.registry-hub --no-out-link
nix-build -A checks.fleet.native-hub-release-pipeline --no-out-link
```

This gate proves exact-byte publication and all four matrix branches. Native
functional qualification on each architecture remains the responsibility of
the platform-specific executors supplied to a real release; the fleet fixture
does not pretend that one x86 VM executes Darwin or Arm binaries.

## Operational boundary

Do not bypass the isolated registry transaction, closed bundle finalizer,
role-separated signing, exact-byte publication receipts, public read-back, or
compare-and-swap channel updates with ad hoc publishes or manual object copies,
on a Hub or a static origin. `andyl/main` remains fail-closed until its
remaining launch gates are complete and its fitness attestations are current. A
experimental publication on a production surface remains explicitly experimental
and cannot be moved across registries.

The normative design and rollout requirements are in
[RFC-0017](../rfcs/0017-canonical-hub-publishing/README.md).
