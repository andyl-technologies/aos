# `andyl/testing` registry runbook

This runbook owns every routine operation for the experimental hosted registry.
The registry is public but unsupported, follows only `edge`, and may be rebuilt
from scratch. Its signing material remains separate from `andyl/main`.

## Preconditions

1. Use the designated maintainer machine and a clean checkout of the current
   `origin/master` commit.
2. Complete the contributor-authorization check in
   [`contributor-licensing.md`](contributor-licensing.md).
3. Deploy and validate that exact Hub build in staging and production using
   [`aos-hub-deployment.md`](aos-hub-deployment.md).
4. Take and verify the backup set in
   [`aos-hub-backup-recovery.md`](aos-hub-backup-recovery.md), unless this is an
   explicitly approved empty rebuild.
5. Load only testing credentials. Main-registry signing keys and production Hub
   tokens must not be present during testing authoring or staging.

Record the source commit, Hub deployment identities, registry base commit and
generation, testing root epoch, operator, UTC start time, and intended release
version in the operation log.

## Inspect live state

Run these read-only checks before and after every mutation:

```sh
aos hub registry show --hub https://aos.andyl.org andyl/testing
aos hub registry releases --hub https://aos.andyl.org andyl/testing
aos hub registry cache-stack show --hub https://aos.andyl.org andyl/testing
aos hub registry cache-stack validate --hub https://aos.andyl.org andyl/testing
aos hub registry mirror show --hub https://aos.andyl.org andyl/testing
```

Repeat them against staging when the operation has a staging phase. Treat a
configured mirror or consumer cache stack as part of the signed release and
recovery inventory; follow the generic
[registry hosting guide](../users/registry/hosting.md) for those subresources.

## Create epoch one

The epoch-one image is pinned to this prepared public anchor:

```text
andyl-testing:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPWdD0Q8y3CRgPouHV03ay7bY2MyQKsKYIyejGL9DVZA
```

Before release, move its already-generated `testing-v1` private key from the
preparation machine's restricted APM key store into the operator secret store,
prove that its derived public key is exactly the line above, and test recovery
from an encrypted independent backup. Do not regenerate a different key under
the epoch-one identity after publishing images.

Verify the restored private key with the AOS-built OpenSSH tool before loading
it into APR:

```sh
derived_public="$(ssh-keygen -y -f "$ANDYL_TESTING_REGISTRY_KEY")"
test "andyl-testing:Ed25519:${derived_public#ssh-ed25519 }" = \
  "$ANDYL_TESTING_TRUST_KEY"
```

For a future registry or trust-root epoch, mint the dedicated OpenSSH Ed25519
registry key before baking its printed public line into the matching profile:

```sh
apr keys generate <epoch-key-id> --registry <slash-free-epoch-alias>
```

Create the epoch-one slash-free authoring clone with the pinned public trust
line and its matching private key, then retain its SHA-256 Git root commit as
the first canonical registry base:

```sh
apr create andyl-testing \
  --trust-key "$ANDYL_TESTING_TRUST_KEY" \
  --trust-key-id testing-v1 \
  --key "$ANDYL_TESTING_REGISTRY_KEY"
```

The Hub slug and signed release identity are `andyl/testing`; the clone name and
trust-line prefix are `andyl-testing`. Generate threshold-signed bootstrap
intents for the exact staging and production deployment identities and run
`aos release bootstrap` once per environment as documented in
[`canonical-releases.md`](canonical-releases.md). Bootstrap refuses a destination
that already contains a publication.

After the `andyl` organization exists in staging, create the public registry
topology there with the ordinary reviewed Hub plan/apply protocol. Plan first:

```sh
aos hub registry create \
  --hub https://aos.staging.andyl.org \
  --org andyl \
  --name testing \
  --visibility public \
  --trust-key "$ANDYL_TESTING_TRUST_KEY" \
  --if-version absent \
  --idempotency-key create-andyl-testing-v1 \
  --plan
```

Review the returned effect manifest, then apply only that exact plan:

```sh
aos hub registry create \
  --hub https://aos.staging.andyl.org \
  --plan-id <plan-id> \
  --confirm-hash <effect-manifest-hash> \
  --yes

aos hub registry show \
  --hub https://aos.staging.andyl.org \
  andyl/testing
```

Bootstrap and qualify the empty base in staging. Only then repeat the topology
plan/apply/show and bootstrap against `https://aos.andyl.org`, using the
production access profile, deployment identity, plan, and idempotency key. The
topology row and `aos release bootstrap` publication are separate: create and
inspect the row first, then install the independently approved empty base.

## Publish the first or a later edge release

Use a calendar SemVer prerelease such as
`2026.9.0-dev.20260904.1`. The plan request must contain:

- `registry: "andyl/testing"` (or the active epoch identity);
- `release_class: "edge"`;
- only an `edge` intended channel;
- the exact current testing registry base commit and generation;
- the staging and production deployment identities already verified above;
- complete package and image decisions and all required signer roles.

Run the complete workflow in [`canonical-releases.md`](canonical-releases.md):

```text
aos release plan
aos release build
aos release finalize-image
aos release finalize-registry
aos release finalize-cache
aos release finalize
aos release tuf
aos release timestamp refresh
aos release compose-surface
aos release timestamp publish
aos release stage
aos release qualify-run
aos release qualify
aos release promote
aos release channel advance
aos release channel complete
```

Do not omit staging qualification even though testing data is disposable. Each
command consumes the prior phase's exact evidence, refuses replacement outputs,
and binds `andyl/testing` into the signed values. Preserve the closed release
bundle, plan request, plan, journal, receipts, TUF set, source checkout identity,
and signer audit records.

After publication, verify anonymously from a clean client that has only the
testing image's baked anchor:

```sh
apm update --registry andyl-testing
apm search aos --registry andyl-testing
```

Also boot the published disk image, confirm `/etc/aos/release-profile`, the
console/SSH warning, and `AOS_REGISTRY=andyl/testing` in `/etc/os-release`. Run
the OCI image and check the same profile and warning files before recording the
rollout complete.

## Update packages

Use `aos maintain` to prepare source updates, not to mutate the registry:

```sh
aos maintain scan
aos maintain report --outdated
aos maintain plan <unit>
# Or plan one atomic update cohort:
aos maintain plan --campaign <cohort>

aos maintain run --plan <plan> --confirm-plan <plan-digest>
aos maintain diff <run> --patch
aos maintain accept <run> --confirm <patch-digest>
aos maintain commit <run> --confirm <run>
aos maintain test <run> --final
aos maintain evidence <run>
aos maintain prepare-pr <run>
aos maintain publish-pr <run> \
  --expected-remote-head absent \
  --confirm <publication-request-digest>
aos maintain observe-pr <run> \
  --authorization-check <required-check-name>
aos maintain handoff <run> --confirm <protected-merge-commit>
```

If the remote branch already exists, replace `absent` with its exact expected
head. `prepare-pr` prints the publication request and confirmation digest;
publication fails closed if either the local candidate or remote head changed.
Merge only after required review and contributor authorization, and record the
observed protected merge with `handoff`. Then create a new edge release from
that merge commit. Do not edit a previous release, tag, immutable TUF metadata
version, or content-addressed Hub object. Channel and timestamp pointers
advance only through their dedicated `aos release` operations.

## Rotate keys without resetting trust

Use the signed APR roster transition for an ordinary registry key rotation:

```sh
apr keys generate <new-id> --registry andyl-testing --add
apr keys list --registry andyl-testing
```

Publish an overlap release, verify a clean client can sync from the old baked
anchor and learn the new active key, and only then retire the old key with the
survivor-vouched APR operation. TUF, release-evidence, qualification, Hub
receipt, Secure Boot, module, PCR, and cache roles follow their own threshold
rotation procedures; never collapse them into the APR key merely because one
machine holds the credentials.

If the Hub registry resource's publication trust set changes, update it with
the complete overlap set, never only the newly generated key. Capture the exact
resource version with `registry show`, plan the update, and apply its returned
plan exactly:

```sh
aos hub registry update \
  --hub https://aos.andyl.org \
  andyl/testing \
  --trust-key "$OLD_TRUST_KEY" \
  --trust-key "$NEW_TRUST_KEY" \
  --if-version <exact-resource-version> \
  --idempotency-key overlap-andyl-testing-keys \
  --plan

aos hub registry update \
  --hub https://aos.andyl.org \
  andyl/testing \
  --plan-id <plan-id> \
  --confirm-hash <effect-manifest-hash> \
  --yes
```

Repeat in staging first. Removing the retired key is a second reviewed update
after the overlap release and clean-client verification.

Other registry configuration changes use the same exact-version plan/apply
contract. Supply only reviewed fields such as `--visibility`, `--crawl-policy`,
`--llms-txt-body`, or `--clear-llms-txt`; review and apply in staging before
repeating against production. Testing remains public. A configuration change
does not authorize a release, key rotation, mirror, cache-stack, or channel
mutation.

## Destructive root reset

Use this only when the testing history or out-of-band root can no longer be
trusted or intentionally becomes incompatible.

1. Stop new testing release work and retain the old public evidence.
2. Select the next unused identity, for example `andyl/testing-v2`, and matching
   alias such as `andyl-testing-v2`.
3. Generate a new root and all role keys. Do not sign the new root with a
   compromised or intentionally abandoned old root.
4. Update the testing profile's identity, `rootEpoch`, URL, alias, and public
   anchor; build new disk and OCI artifacts.
5. Bootstrap the new empty registry in staging, qualify an edge release, then
   bootstrap and publish it in production.
6. Verify old images reject the new registry and new images use only the new
   epoch.
7. Mark the old registry read-only, retain it for the recorded migration window,
   then remove its Hub data according to the approved destructive plan.

Changing only the bytes behind `andyl/testing` is forbidden.

Delete a retired testing registry only after its evidence and object-retention
decision are recorded. Capture its exact resource version with `registry show`,
then use the same two-step mutation contract:

```sh
aos hub registry delete \
  --hub https://aos.andyl.org \
  andyl/testing \
  --if-version <exact-resource-version> \
  --idempotency-key retire-andyl-testing-v1 \
  --plan

aos hub registry delete \
  --hub https://aos.andyl.org \
  andyl/testing \
  --plan-id <plan-id> \
  --confirm-hash <effect-manifest-hash> \
  --yes
```

Repeat independently in staging. Registry deletion is not an R2 backup or
garbage-collection command; reconcile retained objects under the reviewed Hub
storage-retention procedure.

## Audit, rollback, and retirement

Use `aos release verify` with independently supplied public keys for every
retained release bundle. Compare the public deployment probe, registry release,
channel partitions, timestamp, and object digests to the operation log. A bad
edge release is fixed forward with a new immutable release; channel rollback is
an explicit signed channel operation, never an overwrite of release bytes.

For Hub corruption or deletion, follow
[`aos-hub-backup-recovery.md`](aos-hub-backup-recovery.md). Because testing is
disposable, an approved full reset may instead create a new trust-root epoch and
redeploy from empty state. Revoke tokens, archive public evidence, remove the
old image outputs from discovery, and record the terminal registry generation
when retiring an epoch.
