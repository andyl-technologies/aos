# RFC-0017: Canonical AOS Hub publishing

- **Status:** Proposed (design-only). Production publication remains blocked on
  the external-signing, role-separated TUF, promotion, production-image, and
  full-platform-matrix gates listed in
  [`05-implementation-plan.md`](05-implementation-plan.md).
- **Date:** 2026-09-02.
- **Audience:** AOS release maintainers; APM/APR, image, Secure Boot, AOS Hub,
  operations, and security implementers.
- **Build and maintainer host:** A designated, hardened maintainer machine until
  a separate release service or CI system is approved.

## Summary

AOS uses one supported package and system catalog, `andyl/main`. It does not
create separate registries for `stable` or `unstable` maturity. Registry
identity is a trust, ownership, policy, and dependency-resolution boundary;
release maturity is not. AOS expresses maturity with three signed channels
inside `andyl/main`:

- `edge` is the newest integrated development snapshot, cut on changed
  business days with automated smoke evidence and no support promise;
- `candidate` is the weekly release candidate; and
- `stable` is the supported production stream.

All three ship through main's hardware-backed keys and production pipeline, so
a developer following `edge` trusts the same root and exercises the same
delivery path as the supported releases it leads to.

The experimental `andyl/experimental` registry also carries an `edge` channel. It
exists because it has its own trust root, lighter key management and
continuous-deployment infrastructure, and disposable data, not because of
maturity: it is where a change to the release mechanism itself is rehearsed
before it runs against main. Its releases never move into `andyl/main`.

Each channel keeps its existing 256 signed partitions. Those partitions are
rollout rings within a channel, not additional channels or repositories.
Each registry has a staging and a production surface, normally the isolated Hub
deployments `aos.staging.andyl.org` and `aos.andyl.org`, or static origins.
They qualify and serve the same immutable release objects at different stages
and are not distinct AOS distributions. A release is published to destinations
such as `staging/candidate` and `production/stable`; each destination's profile
states what the release must prove before that destination moves.

This RFC's stable release policy selects and closes one four-target package
matrix:
`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`. Both
Linux targets also carry the complete system-image and recovery matrix. Darwin
targets carry packages and their authenticated supporting artifacts only. The
generic package platform schema remains open to other OS, CPU, ABI, and feature
identities.

The release flow is:

```text
protected master commit
        |
        v
hermetic build on maintainer host ---> repeat-build comparison
        |
        v
external hardware-backed signing ----> signed release/evidence bundle
        |
        v
staging surface ----> exact-byte qualification under the destination profile
        |
        v
publish the same immutable objects, without rebuild or re-sign
        |
        v
production surface ----> advance signed channel rings ----> consumers
```

Production signing keys never enter a Nix derivation, the Nix store, the Hub,
the registry clone, a shell environment, or an operator command line. The
maintainer host coordinates builds, ceremonies, uploads, verification, and
evidence retention. Offline or hardware-backed authorities sign only reviewed
digests. The Hub is an authenticated transport and index, not a release-signing
authority.

## Decisions at a glance

| Question | Decision |
| --- | --- |
| How many public registries? | One supported catalog, `andyl/main`, plus the experimental `andyl/experimental` with its own trust root and disposable data. Add another only for a different owner, trust root, legal/distribution policy, or intentionally independent dependency universe. |
| What is the Debian analogue? | AOS channels correspond to Debian's maturity suites. APM registries are closer to independently trusted archives, not suites. |
| Which channels? | `edge`, `candidate`, and `stable` in `andyl/main`; `edge` only in `andyl/experimental`. No environment-named registry. |
| What decides a release's obligations? | The destination's profile: `build` for staging, `smoke` for edge, `functional` for candidate, `soak` for stable. A channel kind selects the same profile on both registries. An emergency is a signed profile override of stable soak and rings, not a class. |
| How is environment recovery proven? | By signed, identity-bound fitness attestations: weekly automated restore and alert checks, quarterly operator exercises. They are not repeated per release. |
| Which package targets? | `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`, subject to the fail-closed package eligibility inventory. |
| Which targets receive images? | Both Linux architectures receive the complete raw/QCOW2/VMDK/VHD and recovery matrix. Darwin receives packages only. |
| How often are registry releases cut? | `edge` on changed business days, `candidate` weekly, `stable` monthly, plus security releases. No release is cut only to satisfy freshness metadata. |
| How often are images built? | For every candidate whose source or inputs can affect the image, and at least once for each monthly stable train. |
| How often are images uploaded? | Every image-bearing candidate goes to staging, then its exact bytes go to production after qualification. Monthly stable rollout reuses those production objects; it does not upload or rebuild them. |
| How are releases versioned? | SemVer-compatible calendar versions: `YYYY.M.P`, no leading zero and no `v`; candidates use `-rc.N`, edge builds use `-dev.YYYYMMDD.N`. |
| Where does release work run? | On the designated maintainer host, under a dedicated release identity and serialized publisher lock. No CI publisher. |
| Can a failed rollout move backward? | No. Stop advancement, preserve evidence, publish a higher fix-forward version, and advance affected partitions. |
| Are current test keys acceptable? | No. Checked-in Secure Boot variants remain fixtures. External signing and a production image profile are launch blockers. |

## Scope

This RFC governs publication of:

- registry package metadata and the complete realized Nix closure;
- package documentation, source outputs, attestations, and license artifacts;
- AOS Linux system toplevels and raw, QCOW2, VMDK, and VHD image encodings;
- normal and recovery UKIs, recovery bundles, image metadata, Secure Boot facts,
  SBAT generations, and expected PCR measurements;
- immutable release manifests and operator evidence; and
- the AOS Hub Worker installer promoted from staging to production.

Machine-specific `host.nix`, customer packages, and organization-owned
registries are outside this public-release policy. They use the same protocol
and trust primitives but have their own owners, cadence, and authorization.

## Load-bearing invariants

1. **One artifact, one identity.** Production receives the exact immutable
   bytes and digests that passed staging. Promotion never rebuilds, reconverts,
   or re-signs them.
2. **Build before signing.** Hermetic build steps cannot read private release
   keys. Signing is a separate finalization stage over a closed manifest.
3. **No key collapse.** Registry, TUF, Nix cache, Secure Boot db, module, PCR
   policy, firmware PK/KEK, provenance, Hub upload, and Hub runtime credentials
   are separate roles.
4. **The Hub is not a root of trust.** Compromise of either Hub deployment or
   its storage must not mint a release, a bootable UKI, a trusted NAR, or a
   valid provenance statement.
5. **Immutable before mutable.** NARs, images, source objects, Git objects, and
   release metadata are uploaded and verified before any public channel pointer
   moves.
6. **Promotion is monotonic.** Release versions, TUF metadata versions,
   published Git history, and consumer channel floors never decrease.
7. **Release failure is fail-closed.** A missing check, signature, source
   artifact, authorization record, recovery artifact, fitness attestation, or
   public verification result blocks the transition.
8. **Staging is production-shaped, not production-trusted.** Provider state,
   secrets, tokens, logs, and disposable smoke registries remain isolated. Only
   a reviewed candidate bundle crosses the environment boundary.
9. **One publisher.** The designated maintainer host holds the sole authoring
   clone and promotion state. Every mutating release operation is serialized
   and recoverable from a hash-chained journal, signed transition evidence, and
   a threshold-authorized completion head.
10. **Security claims match evidence.** A single-host manual build may publish
    signed provenance, but it does not claim SLSA Build L2 or L3.

## Documents

| File | Contents |
| --- | --- |
| [`01-release-model.md`](01-release-model.md) | Registry count, channels, destinations and profiles, versions, cadence, image policy, surfaces and URLs, support, and retention |
| [`02-pipeline.md`](02-pipeline.md) | Artifact inventory, per-destination release journal, profiles and gates, staging qualification, exact production publication, rollout, and recovery |
| [`03-security-and-keys.md`](03-security-and-keys.md) | Threat model, role-separated keys, TUF, Secure Boot finalization, Hub security, and residual risk |
| [`04-maintainer-host-runbook.md`](04-maintainer-host-runbook.md) | Manual maintainer-host procedure and records for routine, stable, emergency, and Hub application releases |
| [`05-implementation-plan.md`](05-implementation-plan.md) | Current capabilities, production blockers, implementation phases, and acceptance criteria |
| [`06-platform-matrix.md`](06-platform-matrix.md) | Four-target package completeness, Linux image matrix, Darwin qualification, and atomic promotion rules |
| [`07-code-architecture-and-delivery-plan.md`](07-code-architecture-and-delivery-plan.md) | Concrete crates, schemas, commands, refactors, workstreams, pull request sequence, and release milestones |

## Relationship to existing designs

This RFC composes rather than replaces:

- the Git-native registry and rollout protocol in
  [`docs/registry/`](../../registry/README.md);
- Secure Boot, measured boot, and registry catalog validation in
  [RFC-0006](../0006-secure-boot/README.md);
- signed A/B recovery in [RFC-0013](../0013-recovery-uki/README.md);
- Hub surface and placement topology in
  [RFC-0012](../0012-hub-surface-topology/README.md);
- authenticated package documentation in
  [RFC-0016](../0016-package-documentation/README.md); and
- the existing manual Hub Worker deployment procedure in
  [`docs/maintainers/aos-hub-deployment.md`](../../maintainers/aos-hub-deployment.md).

Where current tooling cannot enforce this RFC, the implementation plan names an
explicit blocker. Existing fixture-key workflows do not become production
workflows merely because this design has been accepted.

## External design basis

Debian demonstrates the useful separation between one archive and maturity
suites (`stable`, `testing`, and `unstable`), while AOS maps that distinction to
signed channels because channels already carry release selection and rollout
semantics. See the [Debian release overview](https://www.debian.org/releases/)
and [Debian archive FAQ](https://www.debian.org/doc/manuals/debian-faq/ftparchives).

The key separation and freshness design follows the four top-level roles and
offline-root guidance in the
[TUF specification](https://theupdateframework.github.io/specification/latest/).
The external UKI signing boundary uses the engine/provider and private-key URI
model supported by
[`ukify`](https://www.freedesktop.org/software/systemd/man/latest/ukify.html).
Provenance claims use the current
[SLSA provenance](https://slsa.dev/spec/v1.2/provenance) terminology without
claiming a hosted or hardened builder that a maintainer-controlled machine does
not provide.
