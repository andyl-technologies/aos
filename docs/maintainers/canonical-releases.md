# Canonical release coordinator

Canonical AOS releases are driven by one reviewed plan. The plan freezes the
source revision, registry base, complete package and image matrices, required
gates, signer roles, deployment identities, intended channels, and retention
policy before a build or signing effect occurs.

The role boundaries and compromise implications behind this procedure are
defined in [Maintain the AOS trust model](trust-model.md).

The current implementation provides these fail-closed operations:

- `aos release plan` derives the complete four-target package inventory and
  exact Nix derivation outputs, verifies source and contributor-authorization
  preconditions, and writes a new canonical plan;
- `aos release build` realizes every frozen derivation, repeats each build with
  Nix `--check`, and writes build, SBOM, and append-only journal evidence;
- `aos release signer invoke` sends one canonical role-bound request to a
  deployment-configured external signer executable and independently verifies
  its response and public-key identity;
- `aos release finalize-image` binds one exact Linux assembly to the frozen
  plan, performs the complete external signing sequence, and emits one
  verified logical disk, four equivalent download formats, signed UKIs,
  metadata, and recovery bundle;
- `aos release finalize-registry` binds a reviewed atomic registry transaction
  to the validated build report, authors every package-platform entry in an
  isolated clone, obtains externally backed provenance and Git SSHSIGs, and
  creates the release's sole registry commit and annotated tag;
- `aos release finalize-cache` generates the registry closure's static Nix
  cache and obtains a verified external raw Ed25519 signature over every exact
  narinfo fingerprint;
- `aos release finalize` captures a complete payload tree without following
  links, verifies the unsigned manifest as its exact closure, obtains the
  release-evidence signature threshold, verifies the finished bundle offline,
  and atomically emits the bundle plus Finalized-state journal;
- `aos release tuf` verifies the finalized bundle and independently trusted
  root, signs top-level targets, the release-class delegation, and snapshot
  with their separate thresholds, and emits one immutable metadata set;
- `aos release status` reconciles a captured journal without Nix or network;
- `aos release stage` accepts only an already finalized signed bundle, pins the
  canonical staging deployment identity before and after upload, reuses the
  bounded Hub publication protocol, reads every object back anonymously, and
  writes a staging receipt plus successor journal;
- `aos release qualify-run` dispatches each planned gate for every
  artifact-bearing platform to a bounded native adapter, validates exact
  request/response and public-object binding, and obtains a separate external
  qualification-authority signature over the complete aggregate report;
- `aos release bootstrap` installs a threshold-approved first registry base in
  an otherwise empty staging or production Hub;
- `aos release timestamp refresh` renews only the short-lived pointer to an
  already root-authorized immutable snapshot, including recovery after expiry;
- `aos release timestamp publish` reserves the exact next metadata generation,
  commits its prepared Hub surface, and verifies the public bytes;
- `aos release channel complete` proves every planned rollout operation and
  current public partition, then requires threshold release-evidence approval
  of retention and operational handoff before closing the journal; and
- `aos release verify` checks a closed release bundle and optional journal
  offline against explicitly supplied public keys.

Supported publication to `andyl/main` remains forbidden until the remaining
RFC-0017 launch gates and end-to-end operational exercises are complete. The
experimental `andyl/testing` registry may be promoted to the production Hub
only under [`registry-testing.md`](registry-testing.md); that does not satisfy
or bypass any main-registry launch gate.

The canonical release image profile enables external Secure Boot, distinct
module and PCR-policy roles, lockdown, measured boot, encrypted state,
dm-verity, signed recovery, audit, firewalling, and the hardened runtime
preset. It deliberately reports SELinux as excluded: the current immutable
root is not pre-labeled, so enabling the existing policy would overstate the
MAC boundary. SELinux may enter the production profile only with labeled-root
construction and an enforcing boot qualification gate.

## Configure the designated maintainer machine

Enable `aos.services.releaseCoordinator` only in the private machine
configuration. Supply five hermetic wrapper programs: the manually started
content-release driver, restricted TUF timestamp renewal, encrypted backup,
clean-directory restore verification, and operator alert delivery. The public
module deliberately contains no machine identity or deployment-specific path.

The module creates distinct locked service accounts and state directories,
loads each role's disjoint credentials with systemd's credential mechanism,
and rejects credential sources in the Nix store. Content publication has no
timer and begins only with an operator start of
`aos-release-coordinator.service`; this is the no-CI control point. Timestamp
renewal runs every 12 hours by default, backup runs daily, and an offline
network-denied restore check runs weekly. Override calendars only if the TUF
expiry and recovery objectives remain satisfied.

Every failed release, timestamp, backup, or restore unit invokes the isolated
alert service with only the failed unit name and alert-role credentials.
The content-release, backup, and restore jobs share a nonblocking advisory lock;
an overlap fails closed and alerts instead of taking an inconsistent snapshot.
Timestamp renewal uses separate state, identity, policy, and credentials and
does not acquire the content-state lock.

Deployment wrapper programs receive no command-line secrets. They resolve
credential names beneath `$CREDENTIALS_DIRECTORY`, write only beneath their
assigned state/runtime directories, and exec the documented `aos release`
commands. Keep staging and production upload credentials in different
operator steps; do not place both in the manual service's credential set at
the same time.

## Prepare a plan request

Create a reviewed JSON object with schema
`aos.release.plan-request/v1`. Unknown and duplicate fields are rejected. The
request supplies:

- release id, calendar version, and release class;
- one registry authorized by [`registries.md`](registries.md), its exact base
  commit and generation, and a release class/channel allowed by that registry;
- protected source branch, unused immutable source tag, and SHA-256 digest of
  the public contributor-authorization summary;
- explicit decisions for both Linux system-image targets;
- required gates, signer roles and thresholds, staging and production
  deployment ids, intended channel partitions, and retention policy;
- digests of the public evidence and restricted operator policies.

Package eligibility is deliberately absent from the request. Planning derives
every package decision from the versioned Nix inventory for this closed matrix:

| Artifact | `x86_64-linux` | `aarch64-linux` | `x86_64-darwin` | `aarch64-darwin` |
| --- | --- | --- | --- | --- |
| Packages | required cell | required cell | required cell | required cell |
| Images | required cell | required cell | not applicable | not applicable |

Each package cell is either a frozen set of exact derivation, named-output, and
store-path identities or an explicit inapplicable or blocked decision. Stable
and emergency plans reject blocked cells. Darwin receives packages only.

The contributor-authorization summary is a separate public file. Its exact
bytes must hash to the digest in the request. Do not place private employee or
agreement records in the source tree or release bundle.

## Generate the plan

Run planning from a clean source checkout on the designated maintainer host:

```sh
nix run . -- release plan \
  --request release-request.json \
  --contributor-authorization contributor-authorization.json \
  --output release-plan.json
```

Normal edge, candidate, and stable releases require the checked-out commit to
be the local protected branch head and reachable from its protected local or
remote reference. Emergency releases use a reviewed `dplecki/hotfix-*` branch
whose head remains reachable from the protected branch. The requested source
tag must not exist.

Planning is read-only except for the named output. It refuses a dirty checkout
and never replaces an existing output. The resulting file is canonical JSON;
its SHA-256 digest becomes the identity bound by every later operation. Preserve
both the reviewed request and generated plan as release evidence.

## Build the frozen package matrix

Record operator-supplied UTC start and completion times and select a new output
directory:

```sh
nix run . -- release build \
  --plan release-plan.json \
  --output release-build \
  --started-at 2026-09-03T10:00:00Z \
  --completed-at 2026-09-03T12:00:00Z
```

The command realizes the exact named outputs from their frozen derivations and
then asks Nix to rebuild with `--check`. It refuses deriver or store-path drift
and records the exact NAR identity of every upstream source store path (internal
packages instead bind the protected repository source). It writes
`release-plan.json`, `evidence/build-report.json`,
`evidence/sbom.spdx.json`, and `release-journal.jsonl` without replacing an
existing path. A repeated build on one maintainer machine is nondeterminism
evidence, not an independent SLSA builder.

Inspect a copied journal without initializing Nix:

```sh
aos release status --journal release-build/release-journal.jsonl
```

## Exercise an external signer

Signer provider selection and private-key resolution belong to deployment
configuration outside the repository. The executable path must be absolute,
single-linked, and not group- or world-writable. It receives a bounded binary
exchange on standard input under the fixed `sign-exchange-v1` operation: the
domain `aos.release.signer-exchange/v1` plus NUL, an unsigned big-endian request
length, canonical request JSON, an unsigned big-endian payload length, and the
exact public payload bytes. The response is framed with
`aos.release.signer-exchange-response/v1` plus NUL, a 64-bit response-JSON
length and canonical response, then a 64-bit transformed-output length and
those bytes. Detached operations set the final length to zero:

```sh
aos release signer invoke \
  --executable /opt/aos-signers/bin/provider-adapter \
  --request request.json \
  --payload payload.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --verification-identity device-slot-7 \
  --output response.json
```

The coordinator checks the request digest, role, operation, key id, provider
revision, public verification-material digest, and Ed25519 signature. It never
passes a private-key path to the provider.

## Finalize each Linux image

Build the exact unsigned assembly named by the release plan, then invoke the
finalizer once for each Linux target. The signer adapter path and selected key
ids come from restricted deployment configuration; they are never stored in
the source repository or Nix output:

```sh
aos release finalize-image \
  --plan release-plan.json \
  --assembly /nix/store/…-aos-image-production-unsigned-assembly-2026.9.0 \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --signer-key secure-boot-db=db-2026 \
  --signer-key kernel-module=module-2026 \
  --signer-key pcr-policy=pcr-2026 \
  --work /var/lib/aos-release/2026.9.0/x86_64-linux
```

The work path must be absolute and must not exist. It is created with mode
`0700`. The command checks that the assembly store path is an exact artifact in
the matching plan image cell, captures all public inputs without following
links, and pins every executable to the current NAR hash of its owning AOS
store output. Each signer request binds the plan, role, provider revision,
public payload digest, and a fresh 256-bit nonce.

Successful output is under `WORK/finalized`. It contains canonical
`unsigned-image-assembly.json` and `finalized-image-set.json` control files plus
the artifact directory. Disk formats are accepted only after raw, QCOW2,
stream-optimized VMDK, and dynamic VHD independently reconstruct the same
logical GPT bytes. A failed operation leaves no `finalized` directory; retain
or remove the private work path according to the restricted operator policy.

Repeat for `x86_64-linux` and `aarch64-linux`. Darwin targets do not run this
command because their release matrix contains packages only.

## Finalize the isolated registry

Prepare canonical `aos.registry-release-transaction/v1` JSON whose entries are
strictly ordered by build artifact id and whose catalog, store-graph, and policy
digests describe the complete intended result. The catalog surface includes
`containers/`; when publishing OCI, calculate the expected digest with the
exact externally finalized `containers/v1/index.json` sidecar installed. The
command independently checks every package entry against `build-report.json`
and binds the sidecar to its Nix signature input and planned system variant. A
missing, extra, or changed package, version, target, store path, or sidecar
aborts before the output directory is installed.

```sh
aos release finalize-registry \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --transaction registry-transaction.json \
  --container-release final-container/container-release.json \
  --container-signature-input final-container/signature-input.json \
  --source-registry /srv/aos-registry/authoring \
  --output /var/lib/aos-release/2026.9.0/registry \
  --result /var/lib/aos-release/2026.9.0/registry-result.json \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --provenance-key provenance-2026=/media/trust/provenance-2026.pub \
  --registry-key registry-2026=/media/trust/registry-2026.pub \
  --provenance-verification-identity provider-provenance-slot \
  --registry-verification-identity provider-registry-slot \
  --git-name "AOS Release" \
  --git-email release@aos.andyl.org \
  --git-unix-seconds 1788436800 \
  --git-offset-minutes 0
```

Omit both container arguments for a release with no OCI artifact; finalization
removes any prior release's fixed-path sidecar from the new signed tree.
Supplying only one is invalid. The sidecar definition must be either the
compatibility alias `containerImages.aos` with exactly one planned image
variant, or the preferred
`systems.<planned-variant>.build.containers.aos` identity.

The two public key files contain exact
`<local-alias>:Ed25519:<base64>` trust lines: `andyl` for `andyl/main`, or the
epoch-matched `andyl-testing` alias for `andyl/testing`. Their key ids and
provider revisions must be the single-key,
threshold-one Provenance and Registry requirements frozen in the plan. The
single-signature DSSE and Git formats cannot honestly represent a larger
threshold, so the command rejects one rather than counting repeated signatures
outside the signed object.

For provenance, the provider signs the exact DSSE PAE bytes in the
`aos-package-provenance-dsse-v1` SSHSIG namespace. For the commit and tag it
signs Git's exact unsigned object payload in the `git` namespace. The
coordinator verifies request binding, public-material identity, provider
identity, and the SSHSIG cryptographically before accepting each response. It
also checks the provenance trust line against the active, non-revoked
`keys.toml` entry before authoring.

The source registry must be clean at the exact plan base and must not already
contain the release tag. The output and result must not exist. Entries may
write catalog, documentation, provenance, transparency, and store-graph files,
but may not move a ref. Only after the full catalog, store graph, and expected
surface digests pass does the transaction atomically install the isolated
directory, create one signed commit and annotated tag, and generate its static
origin surface. No authoring ref, Hub object, channel, or private key path is
modified by this command.

## Generate and sign the static cache

Generate the cache from the finalized isolated registry, not the mutable
authoring clone:

```sh
aos release finalize-cache \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --registry /var/lib/aos-release/2026.9.0/registry \
  --cache-key cache-2026=/media/trust/cache-2026.pub \
  --verification-identity provider-cache-slot \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --priority 40 \
  --jobs 8 \
  --output /var/lib/aos-release/2026.9.0/cache
```

The command checks that every built package-platform output appears at its
exact registry coordinate before reading the Nix store. It then expands the
complete registry closure, validates blessed store-graph membership, emits
deterministic compressed NARs and unsigned narinfos into a private temporary
directory, and asks the Cache role to sign each canonical Nix fingerprint.

Nix narinfo has a legacy raw `name:base64` Ed25519 signature field and cannot
embed the release request. The provider still receives the complete role,
release, plan, policy revision, payload digest, and fresh nonce; the coordinator
independently verifies the returned raw signature over the exact fingerprint
before appending it. The cache plan must therefore select exactly one cache key
with threshold one. The output becomes visible only after every narinfo is
signed, and existing output paths are never replaced.

## Close and sign the bundle

Assemble a payload directory containing every regular file named by the
unsigned `aos.release.manifest/v1` payload except `release-plan.json`; the
coordinator installs the exact plan itself. The payload includes package NARs,
signed narinfos, registry objects and catalog data, documentation, provenance,
source and license material, SBOM and gate evidence, and both finalized Linux
image sets. It must not contain `release-plan.json`, `release-manifest.json`, a
link, alias, or special file.

```sh
aos release finalize \
  --plan release-plan.json \
  --payload release-payload \
  --manifest-payload release-manifest-payload.json \
  --journal release-build/release-journal.jsonl \
  --signing-key release-1=/media/trust/release-1.pub \
  --signing-key release-2=/media/trust/release-2.pub \
  --verification-identity release-1=provider-release-slot-1 \
  --verification-identity release-2=provider-release-slot-2 \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --recorded-at 2026-09-03T14:00:00Z \
  --output /var/lib/aos-release/2026.9.0/finalized
```

Supply exactly the key count required by the plan's ReleaseEvidence threshold,
with one independently pinned provider identity for each key. The command
captures source files through no-follow handles, copies and hashes them in one
pass, rechecks file metadata and directory membership, and compares every byte
count and SHA-256 value to the manifest. It then asks each external signer to
authorize the exact canonical manifest payload, verifies every response, writes
the signed envelope, and runs the ordinary offline verifier over the completed
tree before making the result visible.

The new output contains `bundle/` and `release-journal.jsonl`. The journal is a
strict successor of the supplied Built journal and binds the manifest digest,
provider operation ids, and signature-response evidence. Neither output path is
reused or replaced.

TUF repository metadata is deliberately not a manifest target. Its delegated
release entry authorizes the finalized manifest envelope, whose artifact list
already closes every bundle payload. Keeping root, targets, delegated targets,
snapshot, and timestamp on the registry metadata surface avoids an impossible
self-reference in which a manifest inventories TUF bytes that themselves name
the manifest or whole-bundle digest. Hub receipts continue to bind the separate
exact-byte bundle digest.

## Construct immutable TUF metadata

Use an independently authenticated, already signed production root. When the
root is a rotation, also supply its predecessor so both old-root and new-root
thresholds are checked. Build the immutable per-release metadata only after the
bundle manifest is final:

```sh
aos release tuf \
  --plan release-plan.json \
  --bundle finalized/bundle \
  --manifest-key release-1=/media/trust/release-1.pub \
  --manifest-key release-2=/media/trust/release-2.pub \
  --root 12.root.json \
  --trusted-root-key root-1=/media/trust/root-1.pub \
  --trusted-root-key root-2=/media/trust/root-2.pub \
  --trusted-root-threshold 2 \
  --targets-key targets-1=/media/trust/targets-1.pub \
  --delegated-key stable-1=/media/trust/stable-1.pub \
  --delegated-key stable-2=/media/trust/stable-2.pub \
  --snapshot-key snapshot-1=/media/trust/snapshot-1.pub \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --targets-version 43 \
  --delegated-version 19 \
  --snapshot-version 44 \
  --targets-expires 2027-09-03T00:00:00Z \
  --delegated-expires 2027-09-03T00:00:00Z \
  --snapshot-expires 2026-12-03T00:00:00Z \
  --now 2026-09-03T14:30:00Z \
  --output finalized-tuf
```

The command requires TUF root, targets, snapshot, timestamp, and the selected
release-class role in every release plan. It verifies that plan key ids and
thresholds exactly equal the trusted root policy, that each supplied public key
matches the root bytes, and that provider revisions come from the frozen plan.
Every signer request binds the plan, final manifest, metadata role and version,
payload digest, operator-policy digest, and a fresh nonce. The complete set is
verified again through the independently supplied root trust before a
no-replace atomic rename makes it visible.

The delegated target names the exact signed `release-manifest.json` envelope by
SHA-256 and byte length. The snapshot names exact versioned root, targets, and
delegated envelopes. Do not copy these files into a publication tree manually;
the surface-composition command below verifies and installs them.

## Refresh TUF timestamp metadata

Timestamp renewal cannot add release content or replace a snapshot. Supply the
current signed root and snapshot, independently authenticated root keys, and
exactly the timestamp-role signature threshold:

```sh
aos release timestamp refresh \
  --plan release-plan.json \
  --root 12.root.json \
  --snapshot 41.snapshot.json \
  --previous-timestamp timestamp.json \
  --trusted-root-key root-1=/media/trust/root-1.pub \
  --trusted-root-key root-2=/media/trust/root-2.pub \
  --trusted-root-threshold 2 \
  --signing-key timestamp-1=/media/trust/timestamp-1.pub \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --version 87 \
  --issued-at 2026-09-03T12:00:00Z \
  --expires 2026-09-05T12:00:00Z \
  --output timestamp.json.next
```

The command verifies the root bootstrap threshold, production role separation,
snapshot signature, root/plan timestamp policy equality, signer public key and
provider identity, exact prior timestamp continuity, and the 48-hour maximum
window. An expired prior timestamp remains cryptographically verifiable at its
recorded issuance instant, so freshness can recover without resetting the
monotonic version. Publish the resulting pointer through its separate Hub
compare-and-swap operation. First atomically compose it with the immutable
registry/cache surface, full verified TUF set, and exact delegated manifest
target:

```sh
aos release compose-surface \
  --plan release-plan.json \
  --bundle finalized/bundle \
  --manifest-key release-1=/media/trust/release-1.pub \
  --manifest-key release-2=/media/trust/release-2.pub \
  --base-surface finalized-registry-surface \
  --root finalized-tuf/12.root.json \
  --targets finalized-tuf/43.targets.json \
  --delegated finalized-tuf/19.stable.json \
  --snapshot finalized-tuf/44.snapshot.json \
  --timestamp timestamp.json.next \
  --previous-timestamp-version 86 \
  --trusted-root-key root-1=/media/trust/root-1.pub \
  --trusted-root-key root-2=/media/trust/root-2.pub \
  --trusted-root-threshold 2 \
  --now 2026-09-03T12:05:00Z \
  --output complete-registry-surface
```

Composition captures the base tree without following links, rejects aliases
and special files, verifies the signed bundle and complete TUF chain, installs
the exact manifest envelope at its delegated release path, retains identical
historical immutable metadata, replaces the timestamp only inside a private
temporary tree, fsyncs the result, and exposes it with a no-replace atomic
rename. Then publish that closed surface:

```sh
aos release timestamp publish \
  --plan release-plan.json \
  --root 12.root.json \
  --snapshot 41.snapshot.json \
  --timestamp timestamp.json.next \
  --previous-version 86 \
  --trusted-root-key root-1=/media/trust/root-1.pub \
  --trusted-root-key root-2=/media/trust/root-2.pub \
  --trusted-root-threshold 2 \
  --registry-surface complete-registry-surface \
  --output timestamp-publication-87
```

The complete surface must contain the exact verified envelopes at
`tuf/timestamp.json` and `tuf/41.snapshot.json`. The coordinator uploads the
surface into an invisible preparing publication. The release-scoped Hub RPC
atomically reserves the next timestamp version and exact object identities
before it commits the mutable publication pointer. A lost response is retried
with the same publication and evidence; a different request for the reserved
version fails closed. The coordinator then performs full anonymous public
read-back and preserves the timestamp plus publication evidence without
replacing an existing output.

## Bootstrap the first Hub registry base

A new staging or production Hub has no publication that can serve as the
compare-and-swap parent of its first release. Do not let the first release
self-authorize that base. Obtain identical
`aos.release.registry-bootstrap-intent/v1` envelopes signed by exactly the
plan's `release-evidence` threshold. The intent binds the environment,
deployment, the plan's exact registry identity, planned base commit, plan
digest, public authority, and approval time.

Install the reviewed base in staging first:

```sh
aos release bootstrap \
  --plan release-plan.json \
  --registry-surface base-registry-surface \
  --environment staging \
  --signed-intent approvals/staging-bootstrap-1.json \
  --signed-intent approvals/staging-bootstrap-2.json \
  --approval-key evidence-1=/media/keys/evidence-1.pub \
  --approval-key evidence-2=/media/keys/evidence-2.pub \
  --output staging-bootstrap
```

Repeat with independent production intent envelopes, the production token,
`--environment production`, and a different output directory. The command
refuses a destination containing any publication, requires the resulting first
publication to have no parent, checks its default commit against the plan,
pins the environment deployment identity before and after upload, and performs
complete and ranged public read-back. Preserve the emitted bootstrap evidence;
all later release publications use this base publication as their explicit
parent. Bootstrap is not a recurring release step.

## Stage a finalized M1 bundle

The staging command always targets `https://aos.staging.andyl.org`; it has no
production URL option. Supply a short-lived staging-only token and the public
manifest keys:

```sh
aos release stage \
  --bundle release-bundle \
  --journal release-bundle/release-journal.jsonl \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --hub-receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --output release-staging
```

Before any upload, the command verifies the complete bundle, signature
threshold, and exact `Finalized` journal precondition. It checks the public
deployment identity before and after upload, reads every committed object back
anonymously through the public registry route, and compares its exact SHA-256
and size. The Hub receipt is verified with an independently pinned,
environment-specific receipt key rather than a release-manifest key. The new
directory contains `staging-receipt.json` and a successor
`release-journal.jsonl`; existing paths are never replaced.

## Run the native qualification matrix

Configure four absolute executable paths. The Linux paths invoke native Linux
test closures. The Darwin paths are credential-free authenticated remote
adapters whose far ends execute on supported Intel and Apple Silicon macOS.
Each adapter reads one canonical request from standard input and writes one
canonical `aos.release.qualification-executor-response/v1` object to standard
output. Successful adapters must not write diagnostics. They download every
object they exercise from the anonymous URLs in the request and verify the
declared length and SHA-256 before testing it.

```sh
aos release qualify-run \
  --bundle release-bundle \
  --staging-receipt release-staging/staging-receipt.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --hub-receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --executor x86_64-linux=/run/aos-release/executors/x86_64-linux \
  --executor aarch64-linux=/run/aos-release/executors/aarch64-linux \
  --executor x86_64-darwin=/run/aos-release/executors/x86_64-darwin \
  --executor aarch64-darwin=/run/aos-release/executors/aarch64-darwin \
  --executor-identity x86_64-linux=linux-x86-v1 \
  --executor-identity aarch64-linux=linux-arm-v1 \
  --executor-identity x86_64-darwin=macos-intel-v1 \
  --executor-identity aarch64-darwin=macos-apple-silicon-v1 \
  --authority-executable /run/aos-release/signers/qualification \
  --authority-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --authority-verification-identity qualification-provider-v1 \
  --executor-nonce 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --authority-nonce abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
  --qualified-at 2026-09-03T12:00:00Z \
  --output qualification
```

Both nonce values are single-use operator inputs. The plan must name a distinct
`qualification` signer role with exactly the public key supplied above. The
command retains each machine-readable executor report, the canonical aggregate
report, its receipt, and the signed receipt. It refuses incomplete executor
configuration even when a particular release has no artifact for one platform.

## Admit signed qualification

After the planned platform executors have tested the exact public staging
objects and returned a signed aggregate qualification envelope, admit it to the
staging Hub:

```sh
aos release qualify \
  --bundle release-bundle \
  --journal release-staging/release-journal.jsonl \
  --staging-receipt release-staging/staging-receipt.json \
  --signed-qualification qualification/signed-qualification.json \
  --qualification-report qualification/qualification-report.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --hub-receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --qualification-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --output release-qualified
```

The command re-verifies the closed bundle and staged journal, verifies the Hub
and qualification signatures with separate trust roots, binds the
qualification policy to the frozen release plan, validates complete passing
gate coverage for every artifact-bearing Linux and Darwin platform, and
requires the receipt to bind the exact canonical aggregate report, staging
receipt, and manifest. It then records the evidence in staging and writes the
report, canonical receipt payloads, and a `Qualified` successor journal without
replacing any existing path. The qualification authority has no Hub, registry,
TUF, cache, channel, or boot-signing credential.

## Promote exact bytes to production

Use a production-only token and independently pinned keys for each evidence
role:

```sh
aos release promote \
  --bundle release-bundle \
  --journal release-qualified/release-journal.jsonl \
  --staging-receipt release-qualified/staging-receipt.json \
  --qualification-receipt release-qualified/qualification-receipt.json \
  --signed-qualification release-qualified/signed-qualification.json \
  --qualification-report release-qualified/qualification-report.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --staging-receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --qualification-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --production-receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --output release-promoted
```

Promotion re-verifies the complete local chain, confirms the production
deployment identity before and after upload, and uploads the unchanged closed
bundle into the isolated production registry. Every object is read back
anonymously in full and with exact prefix and suffix byte ranges. Production
then verifies and imports the signed staging and qualification envelopes,
atomically binds them to its local publication, and returns an
environment-signed production receipt. The command verifies that receipt with
the production-only key, reads the exact envelope back through the anonymous
API, and writes a `Promoted` successor journal without replacing existing
evidence.

## Advance a planned channel range

Advance only a partition range frozen in the release plan, using the exact
generation observed by the operator:

```sh
aos release channel advance \
  --bundle release-bundle \
  --journal release-promoted/release-journal.jsonl \
  --production-receipt release-promoted/production-receipt.json \
  --channel edge \
  --prior-generation 0 \
  --first-partition 0 \
  --last-partition 31 \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --production-receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --channel-receipt-key channel-2026=/media/keys/channel-2026.pub \
  --output release-edge-0-31
```

The Hub commits the generation evidence, channel frontier, and every selected
partition in one transaction. A stale generation, missing promotion, altered
public projection, or range outside the plan fails closed. The command verifies
the production receipt through the anonymous API before mutation, verifies the
signed channel receipt afterward, reads every selected public partition back,
and appends a `Rolling` journal entry. Further planned ranges append
`Rolling`-to-`Rolling` entries with their own generations and receipts; release
completion is a separate retention and handoff decision.

## Complete a rollout

After every planned range has advanced, obtain identical completion decisions
signed by exactly the `release-evidence` threshold frozen in the plan. Each
canonical decision uses schema `aos.release.completion-receipt/v1` and binds the
release, plan, manifest, production receipt, the sorted digest of every channel
receipt, the exact rolling journal-head digest, the frozen retention policy,
affirmative corresponding-source retention, affirmative operational handoff, a
public authority identity, and an RFC 3339 UTC completion time.

Then recheck the complete public rollout and close the journal:

```sh
aos release channel complete \
  --bundle release-bundle \
  --journal release-edge-final/release-journal.jsonl \
  --production-receipt release-promoted/production-receipt.json \
  --channel-receipt release-edge-0-31/channel-receipt.json \
  --channel-receipt release-edge-32-255/channel-receipt.json \
  --completion-receipt approvals/completion-release-evidence-1.json \
  --completion-receipt approvals/completion-release-evidence-2.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --production-receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --channel-receipt-key channel-2026=/media/keys/channel-2026.pub \
  --completion-key evidence-1=/media/keys/evidence-1.pub \
  --completion-key evidence-2=/media/keys/evidence-2.pub \
  --output release-complete
```

The command accepts no access token and performs no Hub mutation. It verifies
one signed channel receipt for every exact plan intent, proves each receipt is
already part of the rolling journal, rejects gaps in per-channel generations,
checks the anonymous production receipt and all public partitions, and verifies
that every completion signer approved identical bytes. The output retains all
receipts and appends the sole `Rolling`-to-`Complete` transition without
replacing an existing path.

## Verify a captured bundle offline

Copy the closed bundle, optional journal, and public verification keys to a
machine that does not need Nix, Git, registry, Hub, or network access. Then run:

```sh
aos release verify ./release-bundle \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --journal ./release-journal.jsonl
```

Repeat `--trusted-key KEY_ID=PATH` to satisfy the manifest threshold. The
verifier rejects links, special files, hard-linked artifacts, path escapes,
non-canonical control documents, digest or size mismatches, invalid signatures,
incomplete matrices, and invalid journal transitions. It streams artifact
digests, so disk images need not fit in memory.

Use public keys from an independently authenticated source. A key shipped only
inside the bundle it is meant to authenticate is not a trust anchor.

## Exercise the complete Hub transition in a fleet

Native Hub deployments terminate TLS in `aos-hub` itself. Configure
`aos.registry-hub.listen` for the public listener, set an HTTPS `externalUrl`,
and supply the `tlsCertificate` and `tlsPrivateKey` credential names. The
listener rejects missing or unexpected SNI and injects HTTPS route evidence
only after a successful rustls handshake; the Hub does not infer security from
forgeable forwarding headers. Keep the private key in the deployment secret
provider and rotate it by replacing the systemd credential followed by a
service restart.

`checks.fleet.native-hub-release-pipeline` is the production-shaped acceptance
test for the online half of this runbook. It boots separate native staging and
production Hub machines with distinct deployment identities, publication keys,
and channel keys using native TLS at the canonical hostnames. The Hub system module
loads every private signing seed and trust map through systemd credentials; a
partial release-evidence configuration fails evaluation.

The publisher is the only machine with `hostStoreMount = true`. It mounts the
host Nix store read-only through the fleet 9p device, binds and registers only
four small prebuilt fixture closures, and exports one NAR for each package cell:
`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`. Those
payloads are not rebuilt into any guest image. Darwin participates only in the
package and qualification matrix; no Darwin image cell is created.

The test initializes both empty native Hubs, creates the public `andyl/main`
delivery topology through reviewed `aos hub` operations, installs the same
signed base publication in both environments, and then invokes the real
porcelain for offline verification, staging, four-platform public-byte
qualification, qualification admission, production promotion, channel
compare-and-swap, and rollout completion. It verifies the final journal state
and anonymous production channel object. The deterministic authorities and TLS
key used by this test are confined to explicit test fixtures and the
`pkgs.aos.testSupport` output; no test authority is installed in a shipped CLI
output.

Run the focused evaluation and fleet gate with:

```sh
nix-build -A checks.registry-hub --no-out-link
nix-build -A checks.fleet.native-hub-release-pipeline --no-out-link
```

This gate proves exact-byte publication and all four matrix branches. Native
functional qualification on each architecture remains the responsibility of
the platform-specific executors supplied to a real release; the fleet fixture
does not pretend that one x86 VM executes Darwin or Arm binaries.

## Operational boundary

Do not bypass the isolated registry transaction, closed bundle finalizer,
role-separated signing, exact-byte staging and promotion receipts, production
read-back, or compare-and-swap channel updates with ad hoc publishes or manual
object copies. `andyl/main` remains fail-closed until its remaining launch gates
and operational exercises are complete. A production-Hub testing publication
remains explicitly experimental and cannot be promoted across registries.

The normative design and rollout requirements are in
[RFC-0017](../rfcs/0017-canonical-hub-publishing/README.md).
