# `andyl/main` registry runbook

Use the shared [qualification contract](qualification.md) and
[release checklist](release-checklist.md). Main's production destinations
select the `smoke`, `functional`, and `soak` profiles of that contract.

`andyl/main` is the supported registry. It is a separate trust and pipeline
assurance domain from `andyl/experimental`: hardware-backed key custody, threshold
signing, and the production publication pipeline, where the experimental registry has lighter
versions of each. Experimental releases and experimental roots never promote into it.
Main carries every channel, including `edge`, so the integration stream runs
through the same keys and pipeline as the releases it leads to.

Follow [Registry key management](registry-key-management.md) for the intended
hardware-backed custody, independent authorities, rotation, and recovery
requirements. GCP/AWS signer integration remains separate implementation work.

Main remains closed until the launch gates in
[`canonical-releases.md`](canonical-releases.md) are complete and a maintainer
records an explicit go-live decision. Before any operation:

1. verify a clean protected-branch source commit and contributor authorization;
2. for each Hub surface, build one immutable Hub installer, deploy it to
   staging, validate it, and promote the exact store path to production;
3. take a complete verified backup and recovery point;
4. confirm with `aos maintain release fitness status` that every fitness
   attestation the planned profiles require is fresh and binding-matched
   (`smoke` requires none);
5. load only main-registry role credentials and the current surface's
   credentials; and
6. record registry base commit/generation, surface identities, key roster,
   operator, and UTC operation window.

## Inspect live state

Run these read-only checks before and after every mutation, in staging first and
then production:

```sh
aos hub registry show --hub https://aos.andyl.org andyl/main
aos hub registry releases --hub https://aos.andyl.org andyl/main
aos hub registry cache-stack show --hub https://aos.andyl.org andyl/main
aos hub registry cache-stack validate --hub https://aos.andyl.org andyl/main
aos hub registry mirror show --hub https://aos.andyl.org andyl/main
```

Use `https://aos.staging.andyl.org` for the staging pass. For a
[static surface](canonical-releases.md#static-surfaces), read its
`.aos-surface` identity, registry head, and channel generation records from the
read-back origin instead. A mirror or consumer
cache stack is a separately reviewed signed configuration; follow the generic
[registry hosting guide](../users/registry/hosting.md) and include it in the
backup and recovery inventory.

## Bootstrap

Create the main authoring base with a dedicated `andyl` registry anchor and
role-separated release/TUF/image authorities. Plan the first main release with
`aos maintain release new --first-release --source-registry <clone>`, which
takes the clone's single root commit as the base, then bootstrap that exact
empty base with threshold-approved intents first in staging and then
production using `aos maintain release step bootstrap`, as described in
[`canonical-releases.md`](canonical-releases.md#bootstrap-the-first-registry-base).
Never reuse a experimental key or import a experimental registry history. Both
bootstrap destinations must be empty for `andyl/main`.

After the `andyl` organization exists in staging, create the Hub topology row
there through a reviewed plan, using the separately backed-up main anchor:

```sh
aos hub registry create \
  --hub https://aos.staging.andyl.org \
  --org andyl \
  --name main \
  --visibility public \
  --trust-key "$ANDYL_MAIN_TRUST_KEY" \
  --if-version "" \
  --idempotency-key create-andyl-main-v1 \
  --plan

aos hub registry create \
  --hub https://aos.staging.andyl.org \
  --plan-id <plan-id> \
  --confirm-hash <effect-manifest-hash> \
  --yes

aos hub registry show --hub https://aos.staging.andyl.org andyl/main
```

Review the first command's returned effect manifest before applying the second.
Bootstrap and qualify the empty base in staging. Only then repeat the topology
plan/apply/show and environment-specific release bootstrap in production.
Creating the topology row does not authorize or publish a base.

## Edge, candidate, and stable releases

Main carries three channels and six destinations:

| Destination | Profile | Obligations |
| --- | --- | --- |
| `staging/edge`, `staging/candidate`, `staging/stable` | `build` | Reproduced, authorized build; channel moves on publication |
| `production/edge` | `smoke` | Automated exact-byte functional checks on the changed targets and cells; no review, soak, or fitness |
| `production/candidate` | `functional` | Every functional claim and package cell, one reviewer per report, transaction review, rollout health, fresh fitness |
| `production/stable` | `soak` | As candidate, plus a complete matrix, qualified (A3) claims, a seven-day soak, `key-rotation` fitness, and rings of 4, 32, 128, and 256 partitions with a reviewed health approval before each ring |

- Edge releases use a `-dev.YYYYMMDD.N` version and plan only the edge
  destinations. They are cut on changed business days, carry no support
  promise, and publish only automated A2 evidence. Edge artifacts bake a
  user-visible warning for that reason.
- Candidate releases use an `-rc.N` version and plan only the candidate
  destinations.
- Final releases use a version without a prerelease component and plan both
  candidate and stable destinations. Publish the bundle to
  `production/candidate` first, then advance it into `production/stable`; the
  stable channel receives the same signed bytes, never a rebuild.
- Main's `edge` and experimental's `edge` are built from the same protected source
  and may share a version and `release/<version>` source tag. Planning accepts
  an existing tag only when it already names the planned commit.
- A change to the build or release mechanism itself is rehearsed in
  `andyl/experimental` before it runs against main's keys and surfaces.

Follow the [release checklist](release-checklist.md), using
[`canonical-releases.md`](canonical-releases.md) for command arguments,
including staging publication, public-byte qualification, production
publication, ring advance, completion approval, TUF timestamp publication, and
offline verification. Preserve the full evidence set for the retention period.
Stable releases require a complete image matrix and all corresponding source.

## Emergency releases

An emergency is a stable release planned with a
[profile override](qualification.md#profile-overrides) of `production/stable`,
not a separate class:

1. Record the incident and its reference.
2. Prepare the fix on a reviewed `dplecki/hotfix-*` branch from the affected
   stable source tag, and make its head reachable from protected `master`.
3. Write the override for the new release ID, naming the incident, a soak of at
   least one day, and rings that end at 256 partitions. Obtain the
   release-evidence threshold of signatures.
4. Run `aos maintain release new` with `--override DIR`, or run it and then
   `aos maintain release advance --to production/stable --override DIR` before any
   build, as described in
   [plan an emergency override](canonical-releases.md#plan-an-emergency-override).

The override changes only soak and rings. Reviews, fitness, the complete
matrix, transaction review, staging publication, and every signature and
integrity check remain required.

## Routine package updates

Use the `aos maintain` workflow documented in the experimental runbook to land source
updates through a reviewed pull request. After merge, the next `edge` release
picks the change up on its changed-business-day cadence, and the next weekly
`-rc.N` candidate carries it toward stable. A stable release is a new plan for a final version, whose one
bundle is published to `candidate` and then `stable`; it is never a retagged
`-rc.N` candidate or a cross-registry channel move.

## Keys, rollback, recovery, and removal

Rotate registry keys through signed overlap and survivor-vouched retirement.
Rotate each other authority within its own threshold/root procedure. Main's
out-of-band root is not disposable: an unplanned root replacement is a security
incident and migration project, not an epoch shortcut.

Mirror every intended Hub publication-trust change with `aos hub registry
update`: supply the complete overlap key set, the exact resource version from
`registry show`, an idempotency key, and `--plan`; apply only the returned
`--plan-id` and `--confirm-hash` with `--yes`. Remove an old key in a separate
reviewed update only after clean clients have learned and accepted its survivor.

Changes to visibility, crawl policy, or `llms.txt` use the same exact-version
plan/apply contract and only the corresponding `registry update` flags. Review
and apply them in staging first. Such a configuration plan never implicitly
changes keys, mirrors, cache stacks, releases, or channels.

Immutable release bytes are never overwritten. Fix a release forward and use a
signed compare-and-swap channel operation when discovery must move. For Hub
state loss, follow [`aos-hub-backup-recovery.md`](aos-hub-backup-recovery.md)
and restore into an isolated instance before changing production routing.

Deleting `andyl/main`, its root keys, corresponding source, release evidence,
or backup history requires a separately reviewed retirement plan. The experimental
registry's disposable-data authorization does not apply to main.

Only after that plan's retention and consumer-migration gates close, capture the
exact version with `registry show`, plan deletion, and review its effect
manifest:

```sh
aos hub registry delete \
  --hub https://aos.andyl.org \
  andyl/main \
  --if-version <exact-resource-version> \
  --idempotency-key <reviewed-key> \
  --plan

aos hub registry delete \
  --hub https://aos.andyl.org \
  andyl/main \
  --plan-id <plan-id> \
  --confirm-hash <effect-manifest-hash> \
  --yes
```

Deleting the Hub topology row never authorizes deletion of object backups,
signing keys, or release evidence.
