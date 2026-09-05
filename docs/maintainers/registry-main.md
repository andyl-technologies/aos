# `andyl/main` registry runbook

Use the shared [qualification contract](qualification.md) and [release checklist](release-checklist.md). Production selects stronger obligations in the same contract.

`andyl/main` is the supported registry. It is a separate trust and lifecycle
domain from `andyl/testing`; testing releases and testing roots never promote
into it.

Main remains closed until the launch gates in
[`canonical-releases.md`](canonical-releases.md) are complete and a maintainer
records an explicit go-live decision. Before any operation:

1. verify a clean protected-branch source commit and contributor authorization;
2. build one immutable Hub installer, deploy it to staging, validate it, and
   promote the exact store path to production;
3. take a complete verified backup and recovery point;
4. load only main-registry role credentials and the current environment token;
5. record registry base commit/generation, deployment identities, key roster,
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

Use `https://aos.staging.andyl.org` for the staging pass. A mirror or consumer
cache stack is a separately reviewed signed configuration; follow the generic
[registry hosting guide](../users/registry/hosting.md) and include it in the
backup and recovery inventory.

## Bootstrap

Create the main authoring base with a dedicated `andyl` registry anchor and
role-separated release/TUF/image authorities. Bootstrap the exact empty base
with threshold-approved intents first in staging and then production using
`aos release bootstrap`. Never reuse a testing key or import a testing registry
history. Both bootstrap destinations must be empty for `andyl/main`.

After the `andyl` organization exists in staging, create the Hub topology row
there through a reviewed plan, using the separately backed-up main anchor:

```sh
aos hub registry create \
  --hub https://aos.staging.andyl.org \
  --org andyl \
  --name main \
  --visibility public \
  --trust-key "$ANDYL_MAIN_TRUST_KEY" \
  --if-version absent \
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

## Candidate, stable, and emergency releases

- Candidate plans use `registry: "andyl/main"`, release class `candidate`, an
  `-rc.N` version, and the `candidate` channel.
- Stable plans use release class `stable`, a release version without a
  prerelease component, and the `stable` channel.
- Emergency plans use the reviewed hotfix source policy, a release version
  without a prerelease component, and the `stable` channel.
- Edge plans are rejected. Publish experimental work to `andyl/testing`.

Run every phase in [`canonical-releases.md`](canonical-releases.md), including
staging, public-byte qualification, production promotion, partitioned channel
advance, completion approval, TUF timestamp publication, and offline
verification. Preserve the full evidence set for the retention period. Stable
and emergency releases require a complete image matrix and all corresponding
source.

## Routine package updates

Use the `aos maintain` workflow documented in the testing runbook to land source
updates through a reviewed pull request. After merge, publish a candidate and
qualify it; a stable release is a new closed release plan and bundle, not a
retagged candidate or a cross-registry channel move.

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
or backup history requires a separately reviewed retirement plan. The testing
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
