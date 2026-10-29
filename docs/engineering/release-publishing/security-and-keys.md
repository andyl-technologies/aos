# Release security and keys

This page describes the threat model of canonical release publishing, the
signer roles the release contracts enforce, the TUF metadata layer, and the
external signing boundary. Custody procedures for each key are in
[Registry key management](../../maintainers/registry-key-management.md); the
registry-level signature and roster model is in
[registry signing and trust](../registry/signing-and-trust.md).

## Threat model

The pipeline assumes any one of these may fail or be compromised independently:

- the public network, DNS, CDN, Hub Worker, Hub database, or object storage;
- a staging credential or staging environment;
- a production upload credential;
- the registry authoring clone or an interrupted publisher;
- the designated maintainer host while it is online;
- one removable key device or one active signing key;
- a package source, build input, converter, or cached build output; or
- a release operator account.

Compromise of an online delivery component may deny service or replay bounded
stale data, but it cannot create trusted package contents or bootable images.
Compromise of an online channel or timestamp key may select or refresh only
metadata already authorized by offline release roles. The design does not claim
to survive simultaneous compromise of the maintainer host, enough offline
signing authorities to meet a threshold, and the human review path. A
single-host manual build may publish signed provenance, but it does not claim a
hosted or hardened builder.

## Signer roles

Every signature is requested for exactly one role
(`SignerRole` in `crates/release/aos-release-format/src/signing.rs`). Private
keys are separate even when two roles use the same algorithm.

| Role | Authorizes |
|---|---|
| `registry` | Registry git commits and tags (git-native continuity and name-binding). |
| `cache` | Nix narinfo signatures for manifest-listed NARs. |
| `tuf-root` | TUF root metadata: role keys, thresholds, and root rotation. |
| `tuf-targets` | Top-level targets and delegations to the release-class roles. |
| `tuf-stable`, `tuf-candidate`, `tuf-edge` | Delegated authorization of a manifest for one release class; a release class requires its matching role. |
| `tuf-snapshot` | One immutable set of already-authorized role metadata. |
| `tuf-timestamp` | The short-lived freshness pointer to an existing snapshot. |
| `secure-boot-db` | Authenticode signatures on systemd-boot and normal/recovery UKIs. |
| `kernel-module` | Kernel module signatures for the production kernel certificate. |
| `pcr-policy` | Measured-boot PCR policies embedded in reviewed UKIs. |
| `provenance` | Provenance DSSE statements. |
| `release-evidence` | The public release manifest, journal evidence, and the completion journal head. |
| `qualification` | One complete passing qualification matrix over exact staging bytes. |
| `channel` | Signed channel operations. |
| `surface-receipt` | Static-surface publication and channel receipts. Hub surfaces sign receipts with the Hub's own receipt key and never use this role. |

A signing response repeats the request digest and signer role, so it cannot be
replayed across releases, registries, roles, or operations. Boot-signing
requests additionally bind the target platform, PE machine type, system
variant, release, and unsigned artifact digest, so a signature for one Linux
architecture cannot satisfy the other's manifest.

## TUF metadata

Each registry surface carries role-separated TUF metadata under `tuf/`
(`crates/release/aos-release-format/src/tuf.rs`): root, top-level targets and
delegations, release-class delegated targets (`stable`, `candidate`, `edge`),
and snapshot metadata. These files are repository metadata outside the
manifest payload closure they authorize. Each surface serves one mutable
`tuf/timestamp.json`, verified as an independently renewable pointer to an
already-authorized snapshot.

A new timestamp continues the one it replaces either by renewing freshness for
the same snapshot or by moving to a later release's snapshot. In both cases the
prior timestamp must verify under the trusted root's timestamp policy at its own
issuance time, the timestamp version increases by exactly one, and a new
snapshot's version must exceed the prior one, so neither pointer can move
backwards. Consumers enforce timestamp expiry when a moving ref selects a
release; explicit immutable pins remain reproducible.

## External signing boundary

Release commands never read private keys. The coordinator
(`crates/release/aos-release-coordinator/src/signer.rs`) runs a signer
executable with the `sign-exchange-v1` protocol: one canonical signing request
on standard input, followed by the exact public payload, and one canonical
response on standard output. A successful exchange writes nothing to standard
error; any diagnostic fails the operation. The coordinator verifies every
response against independently pinned public material.

The executable is an external provider (HSM or remote signing service) named by
the maintainer configuration or `--signer-executable`, or, when none is named,
the file-backed `aos-release-signer` bundled in the release tooling closure.
`aos-release-signer` maps key ids to operator-owned key files through the
configuration named by `--config` or `AOS_RELEASE_SIGNER_CONFIG`; it is intended
for registries such as `andyl/experimental` whose keys are not hardware-backed.
Hermetic build steps never see private keys, and production keys never enter a
Nix derivation, the Nix store, the Hub, the registry clone, a shell
environment, or an operator command line.

## The Hub is transport, not authority

A Hub surface authenticates uploads with short-lived, release- and
environment-scoped credentials and indexes what it receives, but it never signs
release content. Its runtime, seal, and session secrets authorize only that Hub
deployment. Because every published object is bound to the signed manifest and
read back anonymously before a channel moves, a compromised Hub or its storage
can withhold or delay a release but cannot mint a trusted one.
