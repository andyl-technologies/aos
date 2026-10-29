# Release model

This page defines the vocabulary of canonical release publishing — registry,
tier, channel, release class, surface, destination, and profile — and the
policy each one carries. The contracts live in
`crates/release/aos-release-format`; the shipped policy values live in the
Nix-evaluated qualification contract under `qualification/modules/`.

## Registries and tiers

AOS publishes one supported catalog, `andyl/main`, and one experimental
registry, `andyl/experimental`
(`crates/release/aos-release-format/src/registry.rs`). They are separate
security and assurance domains: they differ in key custody, publication
infrastructure, and data lifecycle, not in the maturity of the software they
carry. Maturity is expressed by channels inside a registry, so there is no
environment- or maturity-named registry. Releases never move across
registries.

| Registry | Tier | Channel kinds |
|---|---|---|
| `andyl/main` | `production` | `edge`, `candidate`, `stable` |
| `andyl/experimental` | `testing` | `edge` only |

The experimental registry exists to rehearse changes to the release mechanism
itself against its own trust root and disposable data. A destructive
experimental-root reset advances the registry identity
(`andyl/experimental-v2`, and so on) so an old image cannot silently accept a
replacement out-of-band root.

## Channels and release classes

A channel's *kind* is the prefix before the first `-`, so a per-train channel
such as `stable-2026.3` has kind `stable`. Each channel keeps the registry's
256 signed partitions ([versioning and channels](../registry/versioning-and-channels.md));
those partitions are rollout rings within a channel, not additional channels.

Release versions are SemVer without a `v` prefix, with the first three numeric
fields used as a calendar train (`ReleaseClass::from_version` in
`crates/release/aos-release-format/src/plan.rs`). The prerelease form selects
the release class, and the class limits which channel kinds it may reach
(`class_allows_channel_kind` in `plan/destinations.rs`):

| Version | Class | Allowed channel kinds |
|---|---|---|
| `2026.10.0-dev.20260902.1` | edge | `edge` |
| `2026.10.0-rc.2` | candidate | `candidate` |
| `2026.9.0`, `2026.9.1` | stable | `candidate`, then `stable` |

Months have no leading zero because SemVer forbids leading zeroes; precedence
is ordinary SemVer precedence, and build metadata is not used. Every version is
globally unique and immutable: a failed candidate number is never reused, and a
stable release is the same signed final-version candidate with a later channel
promotion, not a retag. The consumer's monotonic floor is registry-wide, so a
host that took a `candidate` release cannot switch to an older `stable`
release; it waits for `stable` to reach its version.

## Surfaces and destinations

Each registry has a **staging** and a **production** surface. A surface is
either an AOS Hub deployment or a **static origin** (filesystem, S3, or SFTP,
written directly by the maintainer host and read back anonymously). A static
surface proves its identity with a `.aos-surface` file served at its read-back
root, advances channels by compare-and-swap on a signed generation record, and
issues publication and channel receipts signed by the surface-receipt role. A
Hub surface uses its RPC publication protocol and its own receipt key.

Supported surface pairs are Hub staging with Hub production, Hub staging with
static production, and static staging with static production. Static staging
with Hub production is rejected because a Hub cannot verify static staging
receipts (`plan/destinations.rs`).

A **destination** is one `<surface>/<channel>` target, such as
`staging/candidate` or `production/stable-2026.3`. The plan freezes every
destination's selected profile digest, derived gates, soak, and rollout rings,
so changing any of them (including through a signed override) changes the plan
digest:

```json
{"name":"production/stable","surface":"production","channel":"stable",
 "profile":"soak","profile_digest":"sha256:...","soak_seconds":604800,
 "gates":[{"policy_id":"build-integrity","policy_digest":"sha256:...","blocking":true}],
 "rings":[{"partitions":4,"observe_seconds":86400},{"partitions":256,"observe_seconds":0}]}
```

## Profiles

A destination is one `(surface, registry tier, channel kind)` cell of the
publication table (`qualification/modules/destinations.nix`), and it selects a
named **profile** (`qualification/modules/profiles.nix`): the bundle of
requirements, claims, soak, review, matrix completeness, fitness, rollout
rings, and override policy a release must satisfy before reaching it.

| Destination (surface/tier/kind) | Profile |
|---|---|
| `staging/*/*` | `build` |
| `production/testing/edge`, `production/production/edge` | `smoke` |
| `production/production/candidate` | `functional` |
| `production/production/stable` | `soak` |

| Profile | Meaning | Soak | Review | Complete matrix | Rollout |
|---|---|---|---|---|---|
| `build` | Reproducible, authorized build of the complete closure. | none | 0 | no | all 256 partitions |
| `smoke` | Automated exact-byte functional checks on the changed targets. | none | 0 | no | all 256 partitions |
| `functional` | Reviewed functional qualification of every target with fresh environment fitness. | none | 1 | no | all 256 partitions |
| `soak` | Complete-matrix qualification with a week of observation and staged rollout. | 7 days | 1 | yes | 4, 32, 128, then 256 partitions, observing 1, 1, and 2 days |

The contract's assertions enforce that every profile requires
`build-integrity`, that functional profiles keep the native ability
qualification requirements, that a `qualified` claim requires
`rollout-observation` and at least one day of soak, and that rollout rings
strictly increase and end at all 256 partitions.

**Fitness attestations** prove recovery capability of the environment rather
than of one release. Profiles name the fitness kinds they require and their
freshness: `functional` requires weekly storage-restore and alert-delivery
attestations and quarterly authority-recovery and hub-restore exercises;
`soak` adds a quarterly key-rotation exercise. Attestations are signed,
identity-bound inputs (`fitness.rs`) checked against the destination's profile
at publication time; they are not repeated per release.

An **emergency** is not a separate release class. It is a threshold-signed
**profile override** (`profile_override.rs`) of the `soak` profile's soak
window and rings, which is the only profile whose override policy permits
relaxing them. The override is bound into the plan digest.

## Platform matrix

The package matrix contains exactly four targets: `x86_64-linux`,
`aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`
(`crates/release/aos-release-format/src/platform.rs`). Only the two Linux
targets carry system images and recovery artifacts; a Darwin image cell is
invalid. Package eligibility is a fail-closed, Nix-derived inventory
(`inventory.rs`); a profile that requires a complete matrix (`soak`) admits a
release only when every cell is present and qualified.
