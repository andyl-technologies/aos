# Implementation plan and launch gates

## What exists

The repository already implements important parts of the design:

- signed SHA-256 Git registry history, release tags, and name-bound channel
  partition tags;
- monotonic release floors and fix-forward channel advancement;
- `apr release` ordering, a local publisher lock, dry run, resume, immutable
  object upload before mutable surfaces, and deep registry/store validation;
- static Nix cache creation, optional narinfo signing, multiple upload backends,
  and remote membership checks;
- TUF-like root, targets, snapshot, and timestamp envelopes with hashes,
  expiries, versions, thresholds, and root-transition verification;
- signed system-image catalog entries for raw, QCOW2, VMDK, and VHD artifacts;
- derived Authenticode signer, SBAT, PCR 11, disk, recovery, and image-delivery
  facts at publication;
- UEFI Secure Boot, lockdown, module signing, measured boot, TPM-sealed `/var`,
  dm-verity, A/B updates, signed recovery, and end-to-end fleet tests;
- Hub staging/production environment isolation and exact-installer application
  promotion from a designated maintainer host; and
- signed documentation, source retention, Hub audit, topology, placement,
  publication, and cache-retention primitives.

These are necessary but do not make the current fixture workflow a production
publisher.

## Production blockers

Publication of an AOS production image is forbidden until all blockers are
closed:

1. **External signing.** Secure Boot db, PCR policy, module, and Nix-cache keys
   must work through non-exportable provider/HSM interfaces outside Nix builds.
2. **Post-sign assembly.** Final UKIs, modules, recovery bundle, disk images,
   and image metadata must be assembled, verified, and imported without putting
   private keys in a derivation or Nix store closure.
3. **Role-separated TUF.** Root, top-level targets/delegations, stable,
   candidate, edge, snapshot, and timestamp policy and keys must be independent;
   timestamp renewal must not require a registry release.
4. **Release/channel authorization.** A channel key must not authorize new
   release content, and a staging key must not authorize production content.
5. **Closed release bundles.** A versioned manifest, signed state journal,
   exact-byte staging receipt, and public production read-back receipt must be
   machine-validated.
6. **Hub promotion.** Production import must consume a qualified immutable
   bundle with compare-and-swap state rather than rerunning `apr release`.
7. **Production image profile.** A non-fixture system must enforce verified
   boot, lockdown, module signing, measured boot, encrypted state, dm-verity,
   recovery, hardened runtime policy, and production trust anchors.
8. **SELinux truthfulness.** Either an enforcing production policy and labeled
   root pass the release gates, or public claims and profile names explicitly
   exclude SELinux. `hardened` must not imply a disabled control.
9. **Recovery integration.** Firmware enrollment/rotation, TPM/LUKS recovery
   escrow, offline recovery media, and restore procedures must pass together
   with production-like keys.
10. **Canonical route migration.** The Hub route must pass APM and image E2E
    before baked clients move from `cdn.aos.andyl.org`; the old route stays a
    byte-identical compatibility placement through the support window.
11. **Maintainer-host qualification.** Host hardening, identities, backups,
    timestamp service, key inventory, and a clean-host recovery exercise must
    be complete.
12. **Operational rehearsal.** Two candidate releases, one abandoned release,
    one interrupted/resumed upload, one fix-forward rollout, one key rotation,
    and one Hub restore must be executed without production trust.
13. **Supply-chain inventory.** The complete published closure must produce a
    machine-readable SBOM and evaluate a pinned authenticated advisory snapshot
    with signed, expiring dispositions for allowed findings.
14. **Atomic catalog authoring.** The publisher must compose every package,
    system, documentation, source, and license object selected by a plan into
    one isolated registry transaction. A release cannot expose a partially
    updated catalog or require one `apr release` invocation per artifact.
15. **Full platform matrix.** The planner and publisher must close every
    eligible package cell for `x86_64-linux`, `aarch64-linux`,
    `x86_64-darwin`, and `aarch64-darwin`; both Linux targets must publish the
    complete image format and recovery matrix. Native Darwin qualification is
    required before stable publication.

## Phase 1: Manifest and planner

Implement a release-plan schema, final-manifest schema, public evidence schema,
restricted journal, and offline verifier. The schema is closed, versioned, and
uses content digests for every referenced file.

Add a top-level release command that composes existing AOS/APR operations. It
must support read-only `plan`, mutating state transitions, JSON output,
compare-and-swap generation, and offline verification. It does not hide the
lower-level APR repair commands.

Acceptance:

- malformed, incomplete, extra-file, wrong-release, wrong-environment,
  wrong-deployment, stale-base, and digest-mismatch fixtures fail closed;
- plans reject dirty/non-master source and unknown public state;
- state transitions are monotonic and resumable only from matching evidence;
- public evidence contains no secret or private operator data;
- the SBOM and vulnerability decision are bound to the same artifact digests
  as the release manifest;
- multi-artifact plans produce one registry commit and one complete release
  manifest, while any failed member leaves the public catalog unchanged; and
- target eligibility is derived from a fail-closed four-platform inventory,
  with no implicit missing cell or platform-specific stable channel.

## Phase 2: Signer protocol

Define a narrow signing request/response protocol for Ed25519 payloads,
Authenticode, kernel modules, and PCR policies. Support PKCS#11/OpenSSL provider
URIs and a mock provider for hermetic tests. Every request is domain-separated
and policy-bound.

Refactor registry, TUF, narinfo, module, UKI, bootloader, PCR, and recovery
signing callers to use role references. Remove production code paths that need
to copy private inputs into derivations.

Acceptance:

- private material is absent from `.drv` files, input closures, output
  closures, logs, environment captures, and release bundles;
- a provider refuses a key/role, registry, release, or digest mismatch;
- concurrent and replayed requests fail safely; and
- hardware-backed integration tests cover the selected production devices.

## Phase 3: External image finalizer

Split the image build into deterministic unsigned inputs and an external
finalizer. Teach the finalizer to sign modules and PE files, produce PCR policy,
assemble A/B and recovery content, derive all delivery formats, recompute
metadata, verify round trips, and add final outputs to the store by content.

Add a production image system that contains public authorities but no private
key path or test artifact. Assert the complete production security policy at
evaluation and finalization time.

Acceptance:

- production image evaluation contains no private key option value;
- two unsigned builds match;
- every signature and catalog fact is re-derived from finalized bytes;
- x86_64 and AArch64 Linux each produce raw, QCOW2, VMDK, VHD, normal/recovery
  UKIs, and recovery bundles from one finalized logical disk per architecture;
- all four formats reconstruct their architecture's declared logical disk;
- Secure Boot, lockdown, measured boot, encrypted `/var`, dm-verity, A/B
  rollback, and offline recovery pass with production-like hardware tokens; and
- a key, SBAT, PCR, slot, recovery, disk, converter, or metadata mismatch fails
  before upload.

## Phase 4: TUF and channel roles

Replace derived all-role policy with explicit role membership and thresholds.
Publish versioned intermediate roots. Move timestamp metadata to its own mutable
surface and add constrained renewal. Bind channel signers to a channel or
channel class and require release authorization before a partition tag is
accepted.

Acceptance:

- 2-of-3 old/new root transitions and missing-intermediate attacks are covered;
- stable authorization cannot be satisfied by candidate, edge, snapshot,
  timestamp, or channel keys;
- delegated target paths, release version classes, and channel acceptance rules
  are enforced by clients and signing adapters;
- timestamp refresh over a new or unknown snapshot is refused;
- expiry, freeze, rollback, mix-and-match, key-reuse, and threshold attacks are
  covered end to end; and
- stable clients remain fresh across a month with no no-op registry release.

## Phase 5: Hub staged promotion

Add bundle-scoped upload grants, immutable object import, staging qualification
receipts, production import, public read-back receipts, and compare-and-swap
registry/channel/timestamp generations to the shared native/Worker service.

The Hub validates manifests and signatures using public keys. It never calls a
production content signer. Native and Worker behavior must remain equivalent.

Acceptance:

- staging credentials cannot name production resources;
- production rejects a bundle without a valid exact staging receipt;
- altered, rebuilt, re-signed, partial, extra, wrong-base, and wrong-deployment
  bundles fail;
- torn uploads never expose mutable pointers to absent objects;
- simultaneous publishers produce one winner and one clean conflict;
- public ranged image read-back is byte exact; and
- restore/reconcile preserves monotonic published state.

## Phase 6: Maintainer-host automation without CI

Package the release coordinator, signer adapters, verifier, manifest viewer,
and timestamp renewer as AOS packages. Define hardened systemd services/timers
for read-only monitoring, backup, and timestamp refresh. Release construction,
signing, promotion, and channel advancement remain operator-started.

Acceptance:

- services run under separate identities and filesystem/network sandboxes;
- timestamp renewal cannot access build, upload, root, targets, channel, cache,
  or Secure Boot authorities;
- all commands use flake-built AOS tools;
- loss of network, clock, token, signer, disk space, or lock fails closed with
  an actionable journal; and
- the full maintainer-host recovery and key inventory procedure is rehearsed.

## Phase 7: Route and trust migration

Configure staging and production `andyl/main` Hub surfaces, placements,
retention, public routes, and independent smoke registry. Qualify the canonical
Hub route. Publish an overlap image carrying both old and new registry route
configuration and current/next trust anchors, then move the default only after
fleet evidence permits.

Acceptance:

- `apm update`, package install, documentation, source, image discovery,
  complete/ranged image download, and stock Nix substitution pass on the
  canonical route;
- the compatibility CDN route returns byte-identical signed content and has no
  independent writer;
- staging/prod secrets and provider namespaces are proven distinct; and
- route rollback changes delivery only, never content identity or client
  monotonic floors.

## Phase 8: Rehearsal and launch

Using non-production authorities, execute the complete normal, emergency,
abandoned, interrupted, fix-forward, key-rotation, backup/restore, and
maintainer-host-loss scenarios. Archive and independently verify every evidence
bundle.

Production keys are provisioned only after the rehearsals pass and the key
custody record is approved. The first production release starts with no public
consumer channel, is verified through staging and production, initializes
`candidate`, and reaches `stable` only through the complete ring schedule.

## Definition of production-ready

The pipeline is production-ready only when:

- every blocker above has an implemented, tested, documented enforcement
  point;
- no release step relies on operator memory to preserve a security invariant;
- a clean offline verifier can validate plan, bundle, signatures, receipts, and
  state transitions from public keys;
- a clean AOS client can install packages and every advertised image from the
  production Hub route;
- exact staged bytes, exact promoted bytes, and manifest bytes agree;
- a compromised online Hub, upload, timestamp, or channel credential cannot
  authorize new release content or bootable code;
- recovery from loss of the maintainer host, a Hub deployment, object storage,
  one offline signing device, a bad image, and a bad stable ring has been
  demonstrated; and
- the public security statement accurately describes the remaining single-host
  build trust and does not claim SLSA levels the deployment has not earned.
