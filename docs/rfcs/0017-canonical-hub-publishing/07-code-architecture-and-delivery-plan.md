# Code architecture and delivery plan

## Purpose

This document translates the release policy into concrete repository changes.
The implementation is a release subsystem with explicit contracts, not a shell
script around repeated `apr release` invocations. It preserves the existing APR,
Nix-cache, image-verification, and Hub publication mechanisms where their
contracts already satisfy the RFC and adds the missing transaction, signing,
bundle, promotion, and platform-completeness layers.

The implementation has three boundaries:

```text
pure release contract
  schemas, canonical bytes, digests, state transitions, offline verification
                              |
                              v
maintainer-side drivers
  Nix builds, external signers, image finalization, registry authoring, upload
                              |
                              v
Hub admission and promotion
  scoped authorization, exact objects, receipts, compare-and-swap publication
```

The pure contract is shared by every producer and verifier. Maintainer-side
drivers may perform local effects but cannot weaken the contract. The Hub
accepts only a contract-valid bundle and never becomes a content-signing
authority.

## Existing code to retain and refactor

| Area | Existing implementation | Required change |
| --- | --- | --- |
| Package and image catalog schema | [`crates/aos-registry-surface/src/manifest.rs`](../../../crates/aos-registry-surface/src/manifest.rs) | Continue using it as the registry wire schema; add release-wide schemas in a separate pure crate. |
| APR package authoring | [`crates/aos-package/src/registry_ops.rs`](../../../crates/aos-package/src/registry_ops.rs) | Extract authoring and release modules and add a multi-entry isolated transaction. |
| APR release flow | `ReleaseTreeOptions`, `ReleaseStorePublish`, and `release_registry_tree` in [`registry_ops.rs`](../../../crates/aos-package/src/registry_ops.rs) | Stop treating one optional store path as the release unit; separate registry finalization, upload, and channel movement. |
| Registry signatures | [`crates/aos-package/src/security.rs`](../../../crates/aos-package/src/security.rs) | Replace production private-key paths with role-bound signer requests. Retain file keys only for explicit tests. |
| TUF-like metadata | [`crates/aos-package/src/registry/tuf.rs`](../../../crates/aos-package/src/registry/tuf.rs) | Add explicit delegated roles and independent policies, and move timestamp out of immutable release commits. |
| Hub publication admission | [`crates/aos-hub-core/src/service/publication_manifest.rs`](../../../crates/aos-hub-core/src/service/publication_manifest.rs) | Reuse its bounded resumable object admission underneath release-aware staging and promotion. |
| Hub publication client | `HubPublishCmd` in [`crates/aos/src/commands/hub.rs`](../../../crates/aos/src/commands/hub.rs) | Reuse the exact-file uploader; have the release coordinator supply a reviewed bundle instead of rediscovering a directory. |
| Hub protocol | `PublishService` in [`crates/aos-proto/src/proto/aos/hub/v1/hub.proto`](../../../crates/aos-proto/src/proto/aos/hub/v1/hub.proto) | Add release-bundle admission, qualification, promotion, and receipt messages without weakening generic publication. |
| Image construction | [`modules/image/_builder.nix`](../../../modules/image/_builder.nix) and [`pkgs/boot/aos-uki.nix`](../../../pkgs/boot/aos-uki.nix) | Split deterministic unsigned inputs from external signing and final assembly. |
| Secure Boot options | [`modules/base/secure-boot.nix`](../../../modules/base/secure-boot.nix) | Production configuration contains public authorities and signer role references, never private-key paths. |
| Platform inventory | [`pkgs/_platform-support.nix`](../../../pkgs/_platform-support.nix) | Generalize the Darwin-oriented inventory into a closed four-target publication inventory. |
| Flake outputs | [`flake.nix`](../../../flake.nix) | Expose deterministic release inventory and publication roots for all four targets; expose images only for Linux. |

The existing `apr publish`, `apr channel`, cache, origin, and verification
commands remain available as lower-level diagnostics and repair tools. The
top-level release coordinator owns normal release sequencing.

## New crates and module layout

### `aos-release`

Add a pure, no-I/O, wasm-clean workspace crate at `crates/aos-release`. It may
depend on `aos-registry-surface` and dependency-light serialization,
cryptography, hashing, and version crates. It must not depend on `aos`,
`aos-package`, `aos-hub-core`, Git, Nix, an async runtime, or a provider SDK.

```text
crates/aos-release/src/
  lib.rs          crate overview and public module map
  canonical.rs    strict JSON parsing and integer-only RFC 8785 encoding
  digest.rs       bounded SHA-256 identities and domain separation
  platform.rs     exact four-platform vocabulary and matrix cells
  artifact.rs     artifact identities, kinds, and relationships
  plan.rs         frozen release intent
  manifest.rs     finalized closed release bundle
  evidence.rs     public evidence and qualification results
  signing.rs      signer roles and request/response wire types
  state.rs        legal release states and transitions
  receipt.rs      staging, production, channel, and timestamp receipts
  verify.rs       complete offline verification
```

The strict JSON and bundle-boundary primitives currently private to the Hub
topology cutover verifier should move into this crate or into a smaller shared
crate used by both. There must be one implementation of duplicate-member
rejection, canonical JSON, path closure, digest validation, and detached
signature verification.

### `aos-image-finalizer`

Add a focused maintainer-side library at `crates/aos-image-finalizer`. It owns
the external finalization algorithm and public verification of its results. It
may invoke only AOS-built tools supplied explicitly by the caller. Provider
adapters receive opaque key references; private bytes are never represented in
the release schema.

The `aos` CLI calls this library. It is not a daemon and does not publish to the
Hub.

### `aos` release coordinator

Add `crates/aos/src/cli/release.rs` and
`crates/aos/src/commands/release/`. The command implementation owns local
filesystem boundaries, Nix and Git process execution, journal persistence,
signer selection, and Hub calls.

```text
crates/aos/src/commands/release/
  mod.rs
  plan.rs
  build.rs
  finalize.rs
  author.rs
  stage.rs
  qualify.rs
  promote.rs
  channel.rs
  timestamp.rs
  status.rs
  verify.rs
```

The coordinator uses `aos-package` as a library for registry operations and
`aos-remote` for Hub transport. It must not parse APR or Hub human-readable
output.

## Release schemas

### Plan

`ReleasePlanV1` freezes all authority and completeness inputs before a build:

- schema version, release id, SemVer, and release class;
- `andyl/main` registry identity and exact base commit/generation;
- source commit, tree digest, protected-branch reachability, and source tag;
- complete package eligibility matrix and Linux image matrix;
- exact derivations, build tool closures, and repeat-build policy;
- selected gates and their versioned policy identifiers;
- expected staging and production deployment identities;
- signer key ids, roles, thresholds, and provider revisions without secrets;
- intended channels and partitions, expressed as a later operation rather than
  a release mutation;
- retention and corresponding-source requirements; and
- public evidence policy plus the digest of the restricted operator policy.

The planner rejects a dirty source tree, a source commit not reachable from the
protected branch, a reused version, an unknown registry or channel base, an
unclassified package, an implicit missing matrix cell, or unavailable
contributor-authorization evidence.

### Platform matrix

The exact platform enum is closed to:

```text
x86_64-linux
aarch64-linux
x86_64-darwin
aarch64-darwin
```

Every package-platform and image-platform-format cell has exactly one state:

```text
artifact        required content identity and its evidence
not-applicable  versioned eligibility rule and reason
blocked         required work and failure evidence; edge or RC only
```

Darwin cells reject system images, UKIs, recovery, dm-verity, A/B, and Secure
Boot fields. A stable-eligible plan or manifest rejects every `blocked` cell.

### Final manifest and bundle

`ReleaseManifestV1` binds the plan digest to the final result. Each artifact
records:

- a stable logical id and closed artifact kind;
- platform and system variant where applicable;
- exact regular-file path within the bundle;
- byte size, SHA-256, media type, and compression;
- Nix derivation, output, store path, NAR hash, and closure relationships where
  applicable;
- unsigned predecessor and finalized successor relationships;
- logical-disk and delivery-encoding relationships;
- signer role, key id, certificate fingerprint, and verification result; and
- evidence, SBOM, license, source, provenance, recovery, and advisory links.

The bundle manifest inventories every regular file below the bundle root.
Verification rejects an extra file, missing file, symlink, device, hard-link
alias where unique identity is required, absolute path, traversal component,
duplicate logical id, duplicate path, changed size, or digest mismatch.

A bundle uses this conceptual layout:

```text
release-plan.json
release-manifest.json
signatures/
evidence/public/
metadata/registry/
metadata/tuf/
packages/
images/x86_64-linux/
images/aarch64-linux/
sources/
documentation/
licenses/
sbom/
```

Restricted journals and raw operator logs are stored outside the public bundle.
The public evidence records their digests and non-sensitive conclusions.

### State journal

The restricted journal is append-only and hash-chained. Every entry includes
the previous entry digest, plan and manifest digests, expected prior state, new
state, commands or operation ids, timestamps, public evidence digests, and
tool/deployment identities. Signed manifest, Hub, qualification, and channel
evidence authenticate the transitions they authorize. The threshold-signed
completion decision additionally binds the exact rolling journal-head digest,
which anchors the whole predecessor chain before the deterministic final entry
is appended.

The state implementation permits only:

```text
planned -> built -> finalized -> staged -> qualified -> promoted -> rolling -> complete
```

Any active state may transition to terminal `failed`. Resumption requires the
same plan, bundle, previous journal digest, external public state, and immutable
object receipts. A failed version is not reusable.

## CLI contract

The top-level command surface is:

| Command | Effect |
| --- | --- |
| `aos release plan` | Read-only evaluation; writes a new plan only to an explicitly named output. |
| `aos release build` | Realizes the planned matrix twice as required and records build evidence. |
| `aos release finalize` | Uses role-bound external signers, finalizes images and registry metadata, and emits the closed bundle. |
| `aos release compose-surface` | Verifies and atomically composes the registry/cache base, delegated manifest target, immutable TUF set, and fresh timestamp. |
| `aos release stage` | Uploads the exact bundle to the staging Hub and records its receipt. |
| `aos release qualify-run` | Dispatches every planned gate to native Linux and Darwin adapters over exact public staging bytes and signs the aggregate result. |
| `aos release qualify` | Admits a complete signed aggregate qualification to staging and advances the journal. |
| `aos release promote` | Imports the qualified bundle into production without build, conversion, metadata generation, or content signing. |
| `aos release channel advance` | Performs one reviewed compare-and-swap partition transition after production read-back. |
| `aos release channel complete` | Verifies the full signed rollout and threshold-approved retention/handoff evidence before closing the journal. |
| `aos release timestamp refresh` | Refreshes only an already-authorized snapshot with the restricted timestamp role. |
| `aos release status` | Reconciles the journal with immutable local and public state without mutation. |
| `aos release verify` | Verifies plan, bundle, evidence, signatures, receipts, matrix completeness, and state transitions offline. |

Every command supports stable JSON results. Mutating commands require an exact
journal precondition and refuse ambiguous discovery. High-level commands do not
hide lower-level APR or Hub identifiers needed for recovery.

## Atomic registry authoring

Move release-specific code from `registry_ops.rs` into
`crates/aos-package/src/registry/release/` and introduce an API shaped around a
complete transaction:

```text
RegistryReleaseTransaction
  base_commit
  release
  entries[]
  expected_catalog_digest
  expected_store_graph_digest
  expected_policy_digest
```

The implementation:

1. Acquires the publisher lock and verifies the exact base commit.
2. Creates an isolated temporary authoring worktree or clone.
3. Introspects and validates every planned package, platform, documentation,
   source, provenance, image, and store-graph input before publishing a ref.
4. Materializes every catalog change in the isolated tree.
5. Runs deep catalog, store, source, image, license, and matrix validation.
6. Creates exactly one signed registry commit and one release tag.
7. Generates immutable Git/static-cache objects and a closed surface manifest.
8. Returns content identities to the release coordinator without uploading or
   moving a channel.

Calling current `apr publish --no-commit` repeatedly against the real authoring
clone is not an implementation of this transaction: a later failure would
leave partial files and state behind. Compatibility `apr release` may wrap the
new transaction for one-entry development releases, but production uses the
manifest-driven API.

## Signing protocol and adapters

`aos-release` defines the request and response values; effectful adapters live
outside the pure crate. A signing request binds:

- schema and signature domain;
- request id and anti-replay nonce;
- registry, release, plan digest, and manifest digest where known;
- signer role, key id, provider revision, algorithm, and operation;
- platform, system variant, PE machine type, and artifact kind where
  applicable;
- exact payload or unsigned artifact digest;
- TUF metadata version, SBAT generation, PCR selection, or channel name where
  applicable; and
- approval/policy digest without embedding private operator data.

The response returns the request digest, signature, public key or certificate
identity, provider operation id, and public verification data. The coordinator
verifies the response before accepting it.

Production adapters support the selected PKCS#11/OpenSSL provider, TPM, or
hardware-backed SSH signing interfaces. They resolve opaque key references
outside Nix evaluation. A file-backed adapter is compiled or enabled only for
explicit test policy and rejects production release classes.

All current signing call sites migrate to this boundary: registry commits and
tags, DSSE provenance, TUF roles, narinfos, kernel modules, PCR policy,
Authenticode, recovery manifests, release evidence, and channel operations.

## External image finalization

Nix produces an unsigned assembly manifest and deterministic components for
each Linux architecture: kernel and public module certificate, unsigned
modules, root and verity inputs, initrd inputs, unsigned UKI section inputs,
unsigned systemd-boot, recovery inputs, partition layout, public trust material,
and exact AOS-built assembly/conversion tools.

The external finalizer operates in a new output directory and cannot modify the
source checkout or unsigned store outputs. For each architecture it:

1. Signs modules and verifies them against the certificate embedded in the
   production kernel.
2. Reassembles the module-bearing root/initrd inputs.
3. Calculates and signs the declared PCR policy.
4. Assembles and Authenticode-signs slot A, slot B, and recovery UKIs.
5. Authenticode-signs systemd-boot.
6. Constructs one finalized logical A/B disk and its recovery bundle.
7. Derives raw, QCOW2, VMDK, and dynamic VHD encodings from that logical disk.
8. Re-derives image metadata, SBAT, PCR, signer, dm-verity, recovery, and disk
   facts from final bytes.
9. Round-trips every encoding to the same logical disk and runs independent
   public-key verification.
10. Adds final outputs to the store by content and returns their identities.

The production image module exposes public certificates, enrollment artifacts,
PCR public keys, and signer role ids. It has no private-key option. Existing
private-key-path options remain test-only until their callers are migrated and
are rejected by production evaluation.

## TUF and channel implementation

Split `registry/tuf.rs` into metadata, policy, delegation, timestamp, and
verification modules. Root metadata explicitly names distinct root,
top-level-targets, snapshot, and timestamp policies. Top-level targets delegates
disjoint stable, candidate, and edge target paths with their independent key
sets and thresholds.

Versioned root metadata and every intermediate root are immutable. Stable,
candidate, and edge release metadata bind closed release manifests. Snapshot
binds only already-authorized metadata. Timestamp becomes an independently
published mutable object and may advance only over the exact current authorized
snapshot.

Channel operations remain Git-native continuity and rollout records, but their
verifier also requires a compatible TUF release authorization:

- `stable` accepts only stable-authorized final or emergency releases;
- `candidate` accepts candidate- or stable-authorized releases; and
- `edge` accepts any valid release class.

No channel signer can add or modify release content.

## Hub release admission and promotion

Extend `PublishService` rather than replacing its manifest chunks, object
verification, placement fan-out, multipart upload, or immutable-before-mutable
ordering. New release-level requests carry a bundle digest, registry base,
release manifest digest, environment, expected deployment identity, and the
appropriate prior receipt.

The protocol needs operations equivalent to:

```text
BeginReleasePublication
CommitReleasePublication
RecordReleaseQualification
PromoteReleasePublication
GetReleaseReceipt
```

The begin response identifies the existing resumable registry publication
session used to admit and upload objects. Staging commit emits an immutable
environment-signed receipt. Qualification attaches a separately signed result
over that receipt and bundle. Production promotion requires both, checks its
own deployment and compare-and-swap base, and admits only the same object
identities. A public production read-back receipt is available without private
operator data.

Add a migration such as `release_publication.sql` with tables equivalent to:

- `release_bundles` for immutable release identity and environment binding;
- `release_bundle_publications` linking a bundle to existing publication rows;
- `release_qualifications` for exact signed staging results;
- `release_promotions` for staging-to-production continuity; and
- `release_channel_operations` for compare-and-swap rollout evidence.

Database uniqueness and foreign keys enforce one identity per bundle and
environment. Service logic performs the same semantic and signature checks in
native and Worker runtimes. The Hub uses public verification keys only and does
not expose an endpoint that requests content signatures.

## Platform inventory and build outputs

Generalize `_platform-support.nix` so `publicationMatrix` covers all four exact
targets. Evaluation emits a versioned JSON release inventory rather than
requiring Rust to parse Nix source. The inventory includes every discovered
package, eligibility rule, output, version, source identity, target, build-only
classification, blocker, system variant, image format, and required gate.

The flake or default package set exposes deterministic publication roots for:

- all eligible packages on `x86_64-linux` and `aarch64-linux`;
- all eligible packages on `x86_64-darwin` and `aarch64-darwin`; and
- all public system variants and image artifacts on both Linux architectures.

Darwin static checks produce build evidence. Native macOS executors receive a
nonce-bound request containing the complete anonymous staging object inventory,
download content-addressed candidate NARs, and return canonical gate reports
containing artifact digest, target, test policy, executor public identity,
start/finish time, and result. The coordinator validates every response against
the frozen request, then the separate qualification authority signs the exact
aggregate report. Native executors have no registry, channel, Hub, TUF, cache,
boot-signing, or qualification-authority credential.

## Supply-chain evidence

Add a release evidence builder that walks the planned store and source graph and
emits a deterministic SPDX JSON SBOM. It binds package name/version, source
archive, output/store identity, NAR digest, dependency edges, license expression,
documentation, provenance, and corresponding-source relationships.

The vulnerability gate consumes a fixed, authenticated advisory snapshot and a
versioned policy. Its result inventories every finding and an optional signed,
expiring disposition. A stable-eligible release rejects unreviewed critical or
high findings and expired dispositions. The SBOM, advisory snapshot, policy,
scanner closure, and result digests are all release-manifest inputs.

Contributor authorization is obtained from the private system of record and
fails closed when unavailable or indeterminate. Public evidence records only the
source commit, checked contributor identities in their public Git form, policy
version, pass/fail result, time, and signed result digest; it never contains
private acceptance or employment records.

## Delivery workstreams

Four workstreams can proceed independently until their integration milestones:

| Workstream | Owns | Converges at |
| --- | --- | --- |
| Release core | Schemas, planner, journal, verifier, atomic APR authoring | First staging package bundle |
| Signing and images | Signer protocol, role adapters, unsigned image split, finalizer, production image | First image-bearing candidate |
| Hub | Release admission, receipts, promotion, read-back, channel CAS | First no-channel production import |
| Platforms and evidence | Four-target inventory, AArch64 images, Darwin packages/receipts, SBOM/advisories | First stable-eligible candidate |

No workstream may create a compatibility path that silently omits another
workstream's missing evidence. Until convergence, missing required cells or
receipts remain explicit blockers.

## Pull request sequence

Each item is intended to be independently reviewable, tested, and mergeable.
Large Darwin package waves and production image work may require several PRs
under the named item; their public contract does not change between those PRs.

### PR 1: Release contract and offline verifier

- Add `aos-release` and workspace/Nix packaging integration.
- Extract shared strict JSON, canonicalization, path-boundary, digest, and
  detached-verification primitives.
- Implement plan, manifest, matrix, evidence, receipt, and state types.
- Add malicious fixtures for unknown fields, duplicate keys, traversal,
  aliases, extra files, digest mismatch, illegal transitions, and role replay.
- Add `aos release verify` and JSON output.

Exit criterion: an offline verifier can validate or reject a synthetic complete
bundle without Git, Nix, network, Hub, or private keys.

### PR 2: Four-target release inventory and planner

- Generalize `_platform-support.nix` and make unclassified packages fail
  evaluation.
- Emit versioned release-inventory JSON from Nix.
- Add `aos release plan` with protected-source, registry-base, version, matrix,
  gate, deployment, signer-role, and retention checks.
- Add full-matrix evaluation fixtures, including Darwin image rejection and
  stable blocked-cell rejection.

Exit criterion: planning deterministically produces the same digest and exact
cell set from the same source and public state.

### PR 3: Atomic APR registry transaction

- Extract release authoring from `registry_ops.rs`.
- Accept a vector of manifest-derived publish entries.
- Author in isolation, validate the complete tree, commit once, tag once, and
  return a static-surface manifest.
- Separate cache generation, Hub upload, and channel advancement from registry
  finalization.
- Preserve lower-level APR compatibility commands.

Exit criterion: an injected failure at every entry leaves the real catalog and
refs unchanged; a successful multi-platform transaction creates one commit.

### PR 4: Build, evidence, journal, and staging package bundle

- Add `aos release build`, `status`, and journal transitions.
- Run planned derivations and repeat-build comparisons.
- Generate source/license inventory, SPDX SBOM, provenance aggregation, and
  advisory evidence.
- Assemble a package-only closed bundle and feed its reviewed static surface to
  the existing Hub uploader.
- Add staging public read-back over the bundle manifest.

Exit criterion: a non-production edge bundle with explicit blocked cells can be
planned, built, authored, uploaded to staging, read back, and verified without
moving a channel.

### PR 5: Signer protocol and production adapters

- Implement the role-bound request/response protocol and policy verifier.
- Add mock/file test adapter and selected hardware/provider adapters.
- Migrate registry, provenance, narinfo, release-evidence, and channel signing.
- Add scans proving secrets do not enter derivations, closures, environments,
  arguments, logs, or bundles.

Exit criterion: production-class signing works through opaque non-exportable
key references and rejects role, release, registry, digest, replay, and provider
revision mismatches.

### PR 6: Role-separated TUF and independent timestamp

- Implement explicit root and delegated release policies.
- Implement stable/candidate/edge release roles and threshold signatures.
- Publish intermediate roots and add client transition verification.
- Move timestamp to its own mutable surface and add constrained refresh.
- Bind channel acceptance to TUF release class.

Exit criterion: rollback, freeze, mix-and-match, missing-intermediate,
wrong-role, reused-key, and timestamp-over-unknown-snapshot attacks fail end to
end.

### PR 7: External image finalizer and production image

- Split unsigned components and assembly recipes from signed outputs.
- Add module, PCR-policy, UKI, bootloader, recovery, disk, and conversion
  finalization for both Linux architectures.
- Add independent final-byte verification and content-addressed import.
- Add a non-fixture production system profile containing public authorities
  only.

Exit criterion: both Linux architectures produce and boot the complete verified
raw/QCOW2/VMDK/VHD and recovery matrix without a private key appearing in Nix.

### PR 8: Hub release receipts and exact promotion

- Add release-aware protocol messages, shared service logic, and database
  migrations.
- Bind upload grants to bundle, registry, environment, and deployment.
- Emit staging receipts, admit qualification, promote exact objects, and emit
  production read-back receipts.
- Add publication and channel compare-and-swap conflicts and restore/reconcile
  tests for native and Worker runtimes.

Exit criterion: production accepts one exact qualified staging bundle and
rejects altered, rebuilt, re-signed, partial, extra, stale-base, and
wrong-deployment variants.

### PR 9: Full platform qualification

- Complete AArch64 target execution and UEFI image gates.
- Complete Darwin package waves and static Mach-O gates.
- Integrate nonce-bound native Intel and Apple Silicon macOS receipts.
- Exercise package, documentation, cache, source, SBOM, and retention paths for
  all four target identities.

Exit criterion: a stable-eligible candidate has no blocked cell and every
required package/image cell has target-appropriate evidence.

### PR 10: Maintainer automation, rehearsal, and launch

- Package coordinator, verifier, signer adapters, finalizer, manifest viewer,
  and timestamp renewer as AOS packages.
- Add hardened monitoring, backup, and timestamp-refresh services; release
  mutations remain operator-started.
- Run candidate, abandoned, resumed, fix-forward, rotation, restore, and
  machine-loss rehearsals with non-production authorities.
- Complete canonical-route overlap and trust migration.

Exit criterion: every production blocker in
[`05-implementation-plan.md`](05-implementation-plan.md) has an enforcement
point and archived rehearsal evidence.

## Release milestones

| Milestone | Allowed publication | Required implementation | Explicit limitation |
| --- | --- | --- | --- |
| M1: Staging edge | Package-only incomplete bundle to staging | PRs 1-4 | Blocked cells allowed; no production import or channel movement. |
| M2: Signed staging candidate | Package bundle with external release/cache/TUF signing | PRs 1-6 | No production image until external finalization passes. |
| M3: Image-bearing candidate | Complete two-architecture image bundle to staging | PRs 1-7 | Still no production promotion without Hub receipts. |
| M4: Production no-channel import | Exact qualified bundle imported and publicly read back | PRs 1-8 | Consumers cannot discover it through a public channel. |
| M5: Full-matrix candidate | Production `candidate` names a complete qualified matrix | PRs 1-9 | Stable soak and operational rehearsal remain. |
| M6: Stable launch | Canary then cumulative `4 -> 32 -> 128 -> 256` rollout | PRs 1-10 | Fix-forward only after any public pointer moves. |

M1 is the first useful end-to-end implementation target. It proves the plan,
transaction, bundle, journal, staging upload, read-back, and offline verifier
without representing an incomplete matrix or test-key workflow as production.

## Verification strategy

Every PR adds focused Rust unit/integration tests and Nix evaluation checks.
Integration milestones additionally require:

- workspace formatting, lint, documentation, and tests through the flake-built
  development environment;
- `nix-build -A checks.eval --no-out-link`;
- failure injection around every journal transition and registry/Hub commit;
- native and Worker Hub conformance over the same release fixtures;
- offline-verifier fixtures produced independently of the verifier parser;
- x86_64 and AArch64 UEFI, Secure Boot, lockdown, measured-boot, dm-verity,
  recovery, A/B rollback, and format round-trip tests;
- Darwin static and native receipt verification on both architectures;
- TUF root-rotation, threshold, expiry, rollback, freeze, and delegation attack
  tests; and
- a clean-consumer install and ranged image download from the public route.

The implementation is incomplete if a human checklist is the only enforcement
point for a release invariant.

## Non-goals of the implementation

- No CI service publishes releases.
- No platform-specific public registry or channel is added.
- No automatic stable rollout is introduced.
- No Hub runtime receives a release-content private key.
- No production exception permits unsigned content, missing corresponding
  source, implicit matrix omissions, or reuse of failed release bytes.
