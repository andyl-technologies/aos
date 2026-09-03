# Maintainer-host publishing runbook

This is the target operating procedure. Commands that implement the signed
bundle state machine are intentionally not presented as available today. The
current `apr release` and Secure Boot fixture path do not satisfy all of the
production gates in this RFC. The transition to an executable runbook is part
of [`05-implementation-plan.md`](05-implementation-plan.md).

## One-time setup

### Host

Record and verify:

- maintainer-host asset identity, firmware version, Secure Boot state, TPM
  state, encrypted storage recovery, and administrator hardware credentials;
- Nix daemon configuration, sandbox enforcement, allowed builders and
  substituters, disk/reservation limits, and garbage-collection policy;
- default-deny inbound policy and the release-time egress allowlist;
- time synchronization and an alert well inside TUF expiry;
- encrypted backup targets and the last successful restore exercise; and
- dedicated release, timestamp-renewal, and backup service identities.

The normal login account cannot read release state, mint Hub upload grants, or
invoke signing devices. The release identity cannot administer the maintainer
host. The timestamp identity can read only the current authorized snapshot
receipt and can request only timestamp-role signatures.

### Filesystem and state

Use separate permission roots for:

- a clean source mirror and per-release detached checkout;
- the sole `andyl/main` authoring clone;
- unsigned build results;
- external-signing requests and finalized outputs;
- release bundles and append-only journals;
- public evidence and restricted evidence;
- staging and production upload configuration; and
- temporary secret-device mounts.

Paths are deployment configuration, not a wire interface. They are recorded in
the maintainer-host build specification rather than embedded in repository
scripts.
Directories containing release state are mode `0700` or stricter and live on
encrypted storage. Temporary secret mounts use memory-backed storage, disable
core dumps, and are removed at ceremony end.

### Keys and accounts

Inventory all public key ids and devices. Prove that:

- production release devices are non-exportable and require the intended PIN
  and approval flow;
- staging and production Hub/provider credentials address disjoint resources;
- the TUF timestamp credential cannot sign other roles;
- the Hub contains no production content-signing or boot-signing private key;
- a clean image contains current and next public trust anchors where an overlap
  is in progress; and
- break-glass, storage, TPM, firmware, and recovery credentials can be recovered
  by the named custodians.

Do not start publication with an expired certificate, a missing backup, an
untested recovery device, or an unexplained key-inventory difference.

## Begin a release

The operator opens one release session and records its id. Before mutation:

1. Confirm no other content release, Hub deploy, topology change, GC sweep, key
   rotation, or storage migration is active.
2. Update the local source mirror and require a fast-forward to the protected
   remote `master`.
3. Select the exact source commit and inspect its signature, review state, and
   contribution-authorization result.
4. Confirm a clean detached checkout with no ignored or untracked input capable
   of influencing the build.
5. Fetch the public production registry state and record release tags, channel
   partitions, TUF versions, signer roster, Secure Boot catalog, and Hub
   deployment id.
6. Select an unused version according to
   [`01-release-model.md`](01-release-model.md).
7. Generate a dry-run plan and inspect its artifact matrix, gates, key roles,
   four target platforms, two Linux image architecture sets, upload
   destinations, retention roots, and partition changes.
8. Sign the plan with the release-evidence key. Any later input change creates
   a new plan generation and invalidates approvals on the old plan.

## Build and prepare

Run the planned Nix evaluations and builds through the repository flake and AOS
CLI. Do not use `cargo run`, host tools, nixpkgs, or an ad hoc shell pipeline.

For each build:

1. Capture the command, derivation, output paths, NAR hashes, source commit,
   start/finish time, and machine boot identity.
2. Run the selected evaluation, formatting, Rust, package, documentation,
   four-platform package, two-architecture image, VM/fleet, native Darwin,
   license, ABI, and source-retention gates.
3. Force the repeat realization required by the release class and compare the
   unsigned content graph.
4. Verify all package and image metadata against the artifacts rather than the
   build log.
5. Close the unsigned manifest. No file may be added after this point.

If a gate fails or the repeat build differs, end the session as failed. Fix the
source or build definition and start a new plan. Do not bless unexplained output
differences.

## Signing ceremony

The release operator and approving custodian review a human-readable summary of
the closed manifest. It includes source commit, release version, package/image
changes, unsigned digests, Secure Boot and SBAT policy, TUF versions, key ids,
and every gate result.

Connect only the devices required for this release. For each signature:

1. Verify the device identity and role on the trusted display or independent
   manifest viewer.
2. Submit a domain-separated request containing the release and payload digest.
3. Record the device key id and returned signature; never record a PIN.
4. Verify the signature immediately with repository-independent public tooling
   where practical.
5. Disconnect the device before enabling upload credentials.

Run finalization and all post-sign verification. Seal and sign the final bundle
manifest. Compare its allowed output set with the plan. Unexpected files,
missing formats, changed unsigned inputs, wrong signers, or unverifiable
signatures fail the release.

## Stage

Mint or retrieve a short-lived staging publication grant bound to the final
bundle digest. Confirm the CLI is logged into `aos.staging.andyl.org`, the Hub
reports the expected staging deployment id, and the target is staging
`andyl/main`.

Upload under the publisher lock. After the Hub reports completion:

- read every object back through the public staging route;
- verify the registry release from a clean trust store;
- verify all cache, documentation, source, image, and recovery objects;
- exercise full and ranged downloads and cache-control behavior;
- inspect Hub audit events and provider logs; and
- run the release-class qualification suite against downloaded bytes.

Disposable smoke publication uses a staging-only registry and keys. It is not
substituted for the exact `andyl/main` candidate test.

Record the staging receipt and qualification result. A failed staging result
ends the release version; it does not authorize local repair of the finalized
bundle.

## Promote

Promotion begins in a new operator step so staging credentials and production
credentials are never live in the same shell or credential directory.

1. Re-read the final bundle and staging receipt from durable evidence storage.
2. Confirm the source commit and release have not been withdrawn or implicated
   in a new incident.
3. Confirm the production Hub deployment id and topology match the signed plan.
4. Confirm a current backup, recent restore exercise, adequate storage, healthy
   queues/indexers, and no concurrent production mutation.
5. Obtain the bundle-scoped production upload grant.
6. Import immutable objects and verify their public production bytes.
7. Publish the registry snapshot using compare-and-swap against the planned
   base.
8. Verify from a clean APM client using only the image-baked production trust
   anchors.
9. Revoke or let expire the upload grant and remove its local credential.

Do not move a channel in the same approval step as object import. Separating
availability from selection keeps a recoverable boundary between “production
has the bytes” and “consumers are directed to them.”

## Advance channels

For `edge` and `candidate`, review and sign one all-partition advancement after
production read-back passes.

For `stable`, each ring is a separate session:

1. Read the public map twice with caches bypassed and compare it with the last
   signed receipt.
2. Check the target release authorization and manifest digest.
3. Review canary, Hub, support, and security observations for the required
   period.
4. Generate an exact partition compare-and-swap plan.
5. Use only the channel key to sign the advancement.
6. Upload immutable signed partition objects before their mutable discovery
   pointers.
7. Read the changed partitions back publicly and verify tag, release, TUF,
   monotonic floor, and target manifest.
8. Record the receipt and begin the next observation window.

After 256 partitions converge, install permanent release/incident/source/image
retention roots, publish the final evidence status, and close the release lock.

## Refresh TUF timestamp metadata

A systemd timer on the maintainer host may renew timestamp metadata because it
does not build, select, or authorize a release. It runs at least every 12 hours
and:

1. Fetches the current public production snapshot and timestamp.
2. Verifies the complete root/targets/snapshot chain and local version floors.
3. Refuses an unknown snapshot digest, expired authorization, backward version,
   clock anomaly, unhealthy production route, or concurrent release.
4. Requests a timestamp-role signature over the same authorized snapshot with a
   monotonically increasing version and 48-hour expiry.
5. Publishes using compare-and-swap and verifies the public result.
6. Appends a signed renewal receipt.

Failure pages the maintainer before half the validity window has elapsed. It
never falls back to extending an unverified or locally guessed snapshot.

## Emergency release

Open an incident record and name an incident commander. Classify the affected
key, package, image, channel partitions, deployed fleet, and active exploit
risk. Freeze unrelated publication.

The emergency follows the same build, signing, staging, read-back, promotion,
and monotonic rules. The incident commander may shorten soak and widen the
initial stable ring only with a written risk decision. Missing security,
license, source, boot, recovery, or integrity evidence is not waivable.

If the release key is implicated, rotate trust before authorizing new content.
If the Secure Boot db key is implicated, coordinate additive replacement and
firmware revocation with recovery coverage; a registry-only fix is insufficient.
If the maintainer host is implicated, do not rebuild or sign on it. Reconstruct
the documented release environment on a clean approved host and use out-of-band
root recovery.

## Hub Worker release

Use the procedure in
[`docs/maintainers/aos-hub-deployment.md`](../../maintainers/aos-hub-deployment.md)
with these added release rules:

- the selected source commit has passed the applicable release gates;
- the installer store path and deployment id are a signed immutable pair;
- staging and production credentials are loaded in separate sessions;
- production is deployed from the exact staging-qualified installer closure;
- content publication is quiescent during deploy and post-deploy verification;
- an incompatible schema change has a proven restore or forward-repair plan;
  and
- the public deployment-id probe plus authenticated publication/read tests are
  retained in the release journal.

## End the session

At success or failure:

- revoke short-lived credentials and remove temporary credential stores;
- disconnect signing devices and verify no secret-backed process remains;
- threshold-authorize the exact rolling journal head, close the deterministic
  final entry, and copy the journal plus signed evidence to encrypted backup;
- retain required Nix roots, release bundles, source, recovery, and installer
  closures;
- reconcile public Hub, registry, channel, timestamp, and retention state; and
- release the publisher lock.

No cleanup deletes public immutable objects or the only copy of a failed
release's forensic evidence.
