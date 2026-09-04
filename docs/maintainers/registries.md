# Hosted registry policy and runbooks

The hosted Hub uses separate registries for separate trust and lifecycle
domains. Channels are mutable rollout pointers inside a registry; they do not
provide enough isolation for an experimental trust root or disposable data.

| Registry | Local APM alias | Purpose | Allowed release class | Default channel | Data policy |
| --- | --- | --- | --- | --- | --- |
| `andyl/testing` | `andyl-testing` | Experimental integration releases | `edge` | `edge` | Disposable |
| `andyl/main` | `andyl` | Supported releases after graduation | `candidate`, `stable`, `emergency` | `stable` | Durable |

Do not publish an edge release to `andyl/main`, and do not promote a testing
release into main. Graduation is a new main-registry release plan built from a
reviewed source commit; it is not a channel move across registries.

Do not create a separate `andyl/nightly` registry. `edge` is the rapidly moving
channel inside `andyl/testing`; adding a registry is reserved for a genuinely
different trust root, owner, legal boundary, dependency universe, or data
lifecycle. Add later testing rollout rings as signed channels only when they
share the same root and retention policy.

Staging and production are deployment environments, not registry identities.
Both contain independently bootstrapped copies of the same signed registry
identity, while environment-specific deployment ids, publications, receipts,
tokens, databases, and object stores remain isolated. Do not create
`andyl/staging` or sign a staging-only registry name.

The signed identity and local alias are deliberately different. Signed release,
receipt, TUF, and Hub values use the slash-qualified identity. APM configuration
filenames, local clone directories, and trust lines use the slash-free alias.
For example, an `andyl/testing` image contains an
`andyl-testing:Ed25519:...` bootstrap trust line.

## Trust-root epochs

Normal key rotation is an in-band, signed roster/root transition and keeps the
registry identity. If experimental work invalidates the testing history or its
out-of-band root, create a new epoch instead:

```text
andyl/testing       root epoch 1
andyl/testing-v2    root epoch 2
andyl/testing-v3    root epoch 3
```

Never serve a new out-of-band root under an old identity. Old testing images
must fail closed until reinstalled with an image for the new epoch. The old
registry becomes read-only for a bounded migration window and is then removed
according to its disposable-data policy.

## Operation index

- [`registry-testing.md`](registry-testing.md) is the operational runbook for
  creating, releasing, updating, rotating, resetting, auditing, and retiring
  the experimental registry.
- [`registry-main.md`](registry-main.md) is the fail-closed production runbook.
- [`canonical-releases.md`](canonical-releases.md) documents every `aos release`
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
protected source branch, `aos release` freezes and publishes a complete registry
release. A maintenance run must never write a hosted registry directly.

## One-machine operating model

One designated maintainer machine may perform all operations, but it does not
collapse the security domains. Use separate restricted state directories and
credential sets for testing versus main and for staging versus production.
Load only the credentials required by the current phase, verify the selected
Hub deployment before mutation, and serialize release, backup, restore, and
registry-maintenance jobs with the coordinator lock described in
[`canonical-releases.md`](canonical-releases.md).

The machine is not its own backup. Keep an encrypted, access-controlled copy of
private keys, authoring repositories, closed release bundles, operation logs,
and recovery manifests on independently recoverable storage. Exercise restoring
that operator state along with Hub data. A failed or lost maintainer disk must
not force an unrecorded trust-root replacement.

Co-location also does not create an independent approval quorum. Testing may
accept one-machine operation while it remains explicitly experimental, but keep
each signer role as a distinct key and provider identity so later separation is
possible. Do not describe multiple keys available to one operator as independent
human control. `andyl/main` stays closed until its recorded launch decision says
which threshold roles require separate people, devices, or provider accounts.
