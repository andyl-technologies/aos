# Hosted registry policy and runbooks

AOS uses separate registries for separate trust and lifecycle domains.
Channels are mutable rollout pointers inside a registry; they do not provide
enough isolation for an experimental trust root or disposable data.

| Registry | Local APM alias | Purpose | Channels | Destinations | Data policy |
| --- | --- | --- | --- | --- | --- |
| `andyl/main` | `andyl` | The supported registry: hardware-backed keys, strict provenance, durable history | `edge`, `candidate`, `stable` | `staging/edge`, `staging/candidate`, `staging/stable`, `production/edge`, `production/candidate`, `production/stable` | Durable |
| `andyl/experimental` | `andyl-experimental` | Rehearsal of new build, release, and key mechanisms on experimental infrastructure | `edge` | `staging/edge`, `production/edge` | Disposable |

The two registries differ in infrastructure, not in the maturity of what they
carry. `andyl/main` has hardware-backed key custody, threshold signing, and
the production publication pipeline; `andyl/experimental` uses lighter key
management and continuous-deployment infrastructure that is still being
proven, so the registry itself is of a different quality. Maturity is a
channel property: `edge` is the integration stream, `candidate` the weekly
release candidate, and `stable` the supported stream. Main carries all three so
that developers following `edge` trust the same root, and exercise the same
pipeline, as the supported releases they will eventually receive.

Each destination selects a qualification profile, listed in the
[qualification contract](qualification.md#surfaces-and-destinations). A channel
kind selects the same profile on both registries. Experimental epochs
(`andyl/experimental-vN`) carry the same destinations as `andyl/experimental`.

Never move a experimental release into main. Graduation is a new main-registry
release plan built from a reviewed source commit; it is not a channel move
across registries. The experimental registry carries only `edge` because its releases never
graduate: a candidate or stable stream on experimental infrastructure would
be a second supported stream in name only.

There is no emergency release class. An emergency on main is a
[signed profile override](qualification.md#profile-overrides) of
`production/stable` that references an incident record and may shorten only
its soak and rollout rings. Every other obligation still applies.

Do not create a separate `andyl/nightly` registry. `edge` is the rapidly moving
channel inside each registry; adding a registry is reserved for a genuinely
different trust root, owner, legal boundary, dependency universe, or data
lifecycle. The experimental registry carries no other channel; a staged rollout within a channel
uses the destination profile's rings, not additional channels.

The signed identity and local alias are deliberately different. Signed release,
receipt, TUF, and Hub values use the slash-qualified identity. APM configuration
filenames, local clone directories, and trust lines use the slash-free alias.
For example, an `andyl/experimental` image contains an
`andyl-experimental:Ed25519:...` bootstrap trust line.

## Surfaces

Staging and production are publication surfaces, not registry identities.
Both contain independently bootstrapped copies of the same signed registry
identity, while surface-specific identities, publications, receipts,
credentials, and storage remain isolated. Do not create `andyl/staging` or sign
a staging-only registry name.

A surface is either an AOS Hub deployment or a
[static origin](canonical-releases.md#static-surfaces) served from a
filesystem, S3, or SFTP location and read back over HTTPS. A registry does not
require a Hub. A Hub staging surface may pair with a Hub or static production
surface; a static staging surface requires a static production surface.

Staging surfaces are maintainer-facing. A staging destination requires only a
reproduced, authorized build, and its channel moves as soon as the publication
is read back, so executors and reviewers can consume the release exactly as
clients will. Consumers must not configure a staging surface. Production
surfaces are consumer-facing and accept a release only after its staging
publication and the destination's qualification.

## Trust-root epochs

Normal key rotation is an in-band, signed roster/root transition and keeps the
registry identity. If experimental work invalidates the experimental history or its
out-of-band root, create a new epoch instead:

```text
andyl/experimental       root epoch 1
andyl/experimental-v2    root epoch 2
andyl/experimental-v3    root epoch 3
```

Never serve a new out-of-band root under an old identity. Old experimental images
must fail closed until reinstalled with an image for the new epoch. The old
registry becomes read-only for a bounded migration window and is then removed
according to its disposable-data policy.

## Operation index

- [`registry-experimental.md`](registry-experimental.md) is the operational runbook for
  creating, releasing, updating, rotating, resetting, auditing, and retiring
  the experimental registry.
- [`registry-main.md`](registry-main.md) is the fail-closed production runbook.
- [`canonical-releases.md`](canonical-releases.md) documents every `aos maintain release`
  phase and the signed evidence it produces.
- [`trust-model.md`](trust-model.md) defines the authority chain, image-baked
  anchors, signed registry metadata, and runtime trust boundary that these
  procedures preserve.
- [`package-security.md`](package-security.md) defines the package review and
  confinement gates that precede publication.
- [`aos-hub-deployment.md`](aos-hub-deployment.md) deploys one validated Worker
  build to staging and production.
- [`aos-hub-backup-recovery.md`](aos-hub-backup-recovery.md) defines the Hub
  backup set, restore order, and destructive-rebuild boundary.
- [`contributor-licensing.md`](contributor-licensing.md) is a mandatory release
  admission gate.

Package maintenance and registry release are distinct. `aos maintain` discovers,
gates, records, and proposes source updates. After those commits merge to the
protected source branch, `aos maintain release` freezes and publishes a complete registry
release. A maintenance run must never write a hosted registry directly.

## One-machine operating model

One designated maintainer machine may perform all operations, but it does not
collapse the security domains. Use separate restricted state directories and
credential sets for experimental versus main and for staging versus production.
Load only the credentials required by the current phase, verify the selected
surface identity before mutation, and serialize release, backup, restore, and
registry-maintenance jobs with the coordinator lock described in
[`canonical-releases.md`](canonical-releases.md).

The machine is not its own backup. Keep an encrypted, access-controlled copy of
private keys, authoring repositories, closed release bundles, operation logs,
and recovery manifests on independently recoverable storage. The
`storage-restore`, `authority-recovery`, and `hub-restore`
[fitness exercises](release-checklist.md#fitness-exercises) prove that operator
state and surface data can be restored. A failed or lost maintainer disk must
not force an unrecorded trust-root replacement.

Co-location also does not create an independent approval quorum. The experimental registry may
accept one-machine operation while it remains explicitly experimental, but keep
each signer role as a distinct key and provider identity so later separation is
possible. Do not describe multiple keys available to one operator as independent
human control. `andyl/main` stays closed until its recorded launch decision says
which threshold roles require separate people, devices, or provider accounts.
