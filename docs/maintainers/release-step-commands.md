# Release step commands

This page is the reference for `aos maintain release step`, the individual
fail-closed operations that the [release commands](release-commands.md) run
in process. Use it for command arguments, recovery, audit, qualification
snapshots, and inspection of captured evidence. It is part of the
[canonical release coordinator](canonical-releases.md) reference.

## Step commands

`aos maintain release step` exposes the individual operations. Each takes explicit
inputs, verifies everything it consumes, and writes new outputs without
replacing an existing path. The porcelain constructs the same arguments from
the configuration and work directory.

| Command | Operation |
| --- | --- |
| `step contract` | Print the destination table, or one destination's profile and gates |
| `step plan` | Derive and freeze a plan from a request, Git, and the Nix inventory |
| `step build` | Realize and repeat-check every planned output |
| `step signer invoke` | Exercise one external signer exchange |
| `step finalize-image` | Sign and finalize one Linux image assembly |
| `step prepare-registry`, `step finalize-registry` | Author, review, and sign the isolated registry release |
| `step finalize-cache` | Generate and sign the static Nix cache |
| `step assemble`, `step finalize` | Close the payload and threshold-sign the bundle |
| `step verify` | Verify a captured bundle and journal offline |
| `step tuf` | Construct immutable TUF metadata |
| `step record` | Compose the public release record |
| `step compose-surface` | Compose registry, release, and TUF bytes for one destination |
| `step timestamp refresh`, `step timestamp publish` | Renew and publish TUF timestamp metadata |
| `step bootstrap` | Install the first registry base on an empty surface |
| `step publish` | Publish the bundle to one destination |
| `step qualification cases`, `step qualification execute`, `step qualification respond` | Inspect cases; run a configured scenario over exact public objects; bind a scenario report into an executor response |
| `step qualify-run` | Execute and sign one destination's qualification phase |
| `step channel advance`, `step channel complete` | Advance one rollout ring; close a destination's rollout |
| `step status` | Reconcile a captured journal, optionally against its plan |

The former `stage`, `promote`, and `qualify` commands no longer exist.
`step publish` performs both staging and production publication, and
qualification evidence is admitted by the publication and channel steps that
consume it.

### Prepare a plan request

`aos maintain release new` derives the request from the maintainer configuration and
live state. For a manual plan, create a reviewed JSON object with schema
`aos.release.plan-request/v1`. Unknown and duplicate fields are rejected. The
request supplies:

- release id, calendar version, and the release class derived from it;
- one registry authorized by [`registries.md`](registries.md) and its exact
  base commit and generation;
- protected source branch, unused immutable source tag, and SHA-256 digest of
  the public contributor-authorization summary;
- explicit decisions for both Linux system-image targets;
- signer roles and thresholds, the staging and production surfaces (kind,
  origin, optional read-back origin, and identity), the requested destinations
  with any override-accepted soak and rings, the change scope, references to
  accepted profile overrides, and retention policy;
- digests of the public evidence and restricted operator policies.

Package eligibility is deliberately absent from the request. Planning derives
every package decision from native recipe `platformSupport` declarations through
the caller-selected policy in [`pkgs/_target-policy.nix`](../../pkgs/_target-policy.nix).
The release contract selects this matrix:

| Artifact | `x86_64-linux` | `aarch64-linux` | `x86_64-darwin` | `aarch64-darwin` |
| --- | --- | --- | --- | --- |
| Packages | required cell | required cell | required cell | required cell |
| Images | required cell | required cell | not applicable | not applicable |

Each package cell is either a frozen set of exact derivation, named-output, and
store-path identities or an explicit inapplicable or blocked decision. A plan
with a destination whose profile requires a complete matrix (`soak`) rejects
blocked cells. Darwin receives packages only.

The contract's `deferred_platforms` (from
[`qualification/deferred-platforms.nix`](../../qualification/deferred-platforms.nix))
names Linux platforms that ship nothing in this release; the list is currently
empty. The inventory blocks
each of their eligible package cells with `platform-release-deferred`, and the
request must give their image cells a blocked or not-applicable decision; an
artifact there fails planning, and so does any `soak` destination while the list
is non-empty. In each image's `platforms` list, the deferred cell binds the
digest of the retained deferral note:

```json
{"platform": "aarch64-linux",
 "decision": {"state": "blocked",
              "required_work": "Release aarch64-linux images in a later edge release.",
              "failure_evidence": "sha256:<digest of the retained deferral note>"}}
```

The contributor-authorization summary is a separate public file. Its exact
bytes must hash to the digest in the request. Do not place private employee or
agreement records in the source tree or release bundle.

The planner fills in each destination's profile, profile digest, gates, soak,
and rings from the contract. The requested destinations must equal the
contract's destinations for the registry tier, restricted to channels the
release class allows, and the surfaces must form a
[supported pair](release-static-surfaces.md#supported-surface-pairs).

### Generate the plan

Run planning from a clean source checkout on the designated maintainer host:

```sh
aos maintain release step plan \
  --request release-request.json \
  --contributor-authorization contributor-authorization.json \
  --predecessor-manifest predecessor/bundle/release-manifest.json \
  --output release-plan.json
```

`--predecessor-manifest` names the predecessor's manifest payload or signed
envelope, from which planning computes the change scope; without it every
target is affected. To plan with a
[profile override](qualification.md#profile-overrides), add `--override DIR`
(repeatable) for each directory of signed envelopes and `--override-key
KEY_ID=PATH` for each release-evidence key that may approve them.

Releases require the checked-out commit to be the local protected branch head
and reachable from its protected local or remote reference. A plan that
references an accepted [profile override](qualification.md#profile-overrides)
may instead build a reviewed `dplecki/hotfix-*` branch whose head remains
reachable from the protected branch. The requested source tag must not exist,
unless it already names the planned commit: a main edge release and an experimental
edge release of the same version share one `release/<version>` tag on one
protected commit. A tag naming any other commit fails planning.

Planning is read-only except for the named output. It refuses a dirty checkout
and never replaces an existing output. The resulting file is canonical JSON;
its SHA-256 digest becomes the identity bound by every later operation. Preserve
both the reviewed request and generated plan as release evidence.

### Create a first qualification predecessor

When a registry has no prior signed release, create one retained, non-public
qualification snapshot from an earlier protected source revision and an older,
distinct calendar version. Its plan request uses the complete current contract
and normal package and image matrices, with exactly these reserved fields:

```json
{
  "release_id": "qualification-snapshot-2026.9.0-dev.20260904.0",
  "version": "2026.9.0-dev.20260904.0",
  "source": {
    "source_tag": "qualification-snapshot/2026.9.0-dev.20260904.0"
  },
  "destinations": []
}
```

The `qualification_predecessor` field is absent. The fragment shows the
relationship among the reserved values; retain all other required request
fields. Any other missing-predecessor shape fails planning, and the reserved
release id and source tag cannot be used by a plan that has a predecessor.

Snapshots are not driven by `aos maintain release new`. Run the ordinary `step plan`,
build, image-finalization, isolated-registry, cache, manifest, TUF,
timestamp-refresh, and surface-composition steps. Use the same release-evidence
and image authorities required by the contract. Do not run `bootstrap`,
`publish`, `qualify-run`, `record`, `timestamp publish`, or `channel`: those
steps reject qualification snapshots before any surface effect. The snapshot
does not claim that it passed an update from an earlier installation; its
purpose is to provide the first exact installed source for the candidate's
update and rollback cases.

Verify the final bundle offline with independently supplied manifest keys and
retain the JSON result:

```sh
aos --json maintain release step verify qualification-snapshot/bundle \
  --journal qualification-snapshot/release-journal.jsonl \
  --trusted-key release-1=/media/trust/release-1.pub \
  --trusted-key release-2=/media/trust/release-2.pub \
  > qualification-snapshot-verification.json
```

The first public plan copies `verification.release_id` and
`verification.manifest_digest` into `qualification_predecessor` together with
the same registry identity. Preserve the closed snapshot bundle, journal,
verification output, public keys, and source tag. The Linux image executor must
verify that bundle again and exercise the exact snapshot-to-candidate transition;
a descriptor without the retained signed bytes is insufficient.

### Build the frozen package matrix

Record the UTC start time and select a new output directory. The command
captures the completion time after realization, repeat-building, and build
evidence collection finish:

```sh
aos maintain release step build \
  --plan release-plan.json \
  --output release-build \
  --started-at 2026-09-03T10:00:00Z
```

The command realizes the exact named outputs from their frozen derivations and,
for a production-tier plan, asks Nix to rebuild them with `--check`. It refuses deriver or store-path drift
and records the exact NAR identity of every upstream source store path (internal
packages instead bind the protected repository source). It writes
`release-plan.json`, `evidence/build-report.json`,
`evidence/sbom.spdx.json`, and `release-journal.jsonl` without replacing an
existing path. A repeated build on one maintainer machine is nondeterminism
evidence, not an independent SLSA builder.

The registry tier decides whether the `--check` rebuild runs. A
production-tier plan (`andyl/main`) runs it for every planned derivation and
fails the step, naming every derivation whose rebuild differed or failed. A
testing-tier plan (`andyl/experimental` and its epochs) accepts unreproduced
outputs, so a rebuild could not change its outcome: it skips the pass and
records every output as `not-checked`. Report validation and `step assemble`
accept only `reproduced` outputs for production, and accept `not-checked` and
`not-reproduced` outputs for testing. There the `build-integrity`
`repeat-build` observation states that no repeat build ran.

Inspect a copied journal without initializing Nix using
[`step status`](#inspect-a-captured-journal).

### Exercise an external signer

Signer provider selection and private-key resolution belong to deployment
configuration outside the repository. Every step that signs takes an optional
`--signer-executable` (`--authority-executable` for `qualify-run`,
`--executable` for `signer invoke`) and an optional `--signer-config`
(`--authority-config` for `qualify-run`). Without an executable, the step runs
the [bundled file-backed signer](#file-backed-signer-for-registries-without-an-hsm)
from the release tooling closure and requires the configuration. A given
configuration path reaches the signer process as `AOS_RELEASE_SIGNER_CONFIG`.

The executable path must be absolute, single-linked, and not group- or
world-writable. A read-only file inside the Nix store may have additional hard
links, because store optimisation links identical store files together without
making them writable. The executable receives a bounded binary
exchange on standard input under the fixed `sign-exchange-v1` operation: the
domain `aos.release.signer-exchange/v1` plus NUL, an unsigned big-endian request
length, canonical request JSON, an unsigned big-endian payload length, and the
exact public payload bytes. The response is framed with
`aos.release.signer-exchange-response/v1` plus NUL, a 64-bit response-JSON
length and canonical response, then a 64-bit transformed-output length and
those bytes. Detached operations set the final length to zero:

```sh
aos maintain release step signer invoke \
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

#### File-backed signer for registries without an HSM

`aos-release-signer` implements the exchange above for deployments whose
private keys are operator-owned files, which is the approved custody model for
`andyl/experimental`. It reads a JSON configuration named by
`AOS_RELEASE_SIGNER_CONFIG` or `--config` that maps each public key id to a
private-key file, the roles it may serve, and the verification identity the
coordinator pins.

The `release-tooling` closure bundles the signer, so it always comes from the
same source revision as the coordinator and accepts the same registries. Leave
`[signer] executable` unset and set `[signer] config` to the JSON
configuration; the coordinator spawns the bundled copy with
`AOS_RELEASE_SIGNER_CONFIG` set to that path. The configuration and the
private keys it names are the only signer material in restricted deployment
storage: neither belongs in the repository or the Nix store, and no signer
binary or wrapper script is kept beside them. Inside `nix develop .#release`
the same binary is on `PATH` as `aos-release-signer`.

The adapter refuses any request whose provider revision or registry is not in
its configuration, whose key is not authorized for the requested role, or whose
payload does not reproduce the request digest. It signs Ed25519 request
digests and raw payloads in process, produces OpenSSH SSHSIG signatures for the
`registry` and `provenance` roles from an OpenSSH key whose roster trust line is
part of the configuration, signs measured-boot PCR policies and recovery
manifests with RSA, and delegates Authenticode and kernel-module signatures to
the `sbsign` and `openssl` executables named in its `tools` table. Its
`verification_material_digest` is always the SHA-256 of the configured public
file or trust line, so those bytes must be identical to the public copies the
image assembly and coordinator pin independently.

`aos-release-signer show` prints every configured key's public identity for
comparison with the public key inventory. `aos-release-signer sign-evidence
--key-id KEY --payload intent.json --output approval.json` wraps a canonical
approval payload, such as an `aos.release.registry-bootstrap-intent/v1`
document, in the `aos.hub.signed-release-evidence/v1` envelope that
`step bootstrap`, `step qualify-run --review-receipt`, `step channel
complete`, and profile overrides consume.

### Finalize each Linux image

Build the exact unsigned assembly named by the release plan, then invoke the
finalizer once for each Linux target. The signer adapter path and selected key
ids come from restricted deployment configuration; they are never stored in
the source repository or Nix output:

```sh
aos maintain release step finalize-image \
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

### Prepare and finalize the isolated registry

Author the isolated registry once, before review. `prepare-registry` derives
every entry from the validated build report, obtains the planned provenance
signatures, validates the complete OCI layout and records its typed descriptor
graph with the exact finalized sidecar, regenerates and verifies
registry catalog TUF metadata over the current authored files, calculates all
registry surface digests, and writes the canonical
`aos.registry-release-transaction/v1` review file. It leaves the retained
registry clone uncommitted at the planned base ref.

```sh
aos maintain release step prepare-registry \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --container-release final-container/container-release.json \
  --container-signature-input final-container/signature-input.json \
  --container-layout final-container/layout \
  --source-registry /srv/aos-registry/authoring \
  --output /var/lib/aos-release/2026.9.0/registry \
  --transaction registry-transaction.json \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --provenance-key provenance-2026=/media/trust/provenance-2026.pub \
  --provenance-verification-identity provider-provenance-slot \
  --registry-key registry-2026=/media/trust/registry-2026.pub \
  --registry-verification-identity provider-registry-slot
```

Review the generated transaction and the retained registry diff together. Its
entries are strictly ordered by build artifact id, and its catalog,
store-graph, and policy digests bind the complete authored tree. Do not edit or
regenerate either input after review. Finalization revalidates the plan, build
report, OCI input, every entry, the store graph, base ref, and all three surface
digests before it requests either Git signature. Stale catalog metadata from
the base commit cannot be carried into a changed candidate or removed to bypass
verification.

Catalog TUF uses the active registry roster authority and the committed catalog
root's bootstrap and rotation rules. The source-built provider signs exact
catalog-alias/role/version-bound JSON through `CatalogTuf` requests in the
`aos-registry-tuf-v1` SSHSIG namespace. It does not use the distribution bundle's
separate TUF authorities or its payload digest domains. The outer request binds
the canonical Hub registry identity while the catalog context preserves the
local alias consumed by APM. APR's file-key producer
and this external provider path share metadata construction and verification;
preparation freezes the resulting `tuf/` bytes in the transaction policy digest.
The highest published root metadata version supplies rotation authority;
each role's floor is its maximum version across all published tags. A hotfix
on an older release line therefore continues metadata history even when its
source workspace starts from an older release.
The reviewed transaction also binds the optional complete container graph;
finalization evidence carries that graph into the stage inventory.

Each package/platform coordinate must contain exactly one `out` output. That
output remains the installable `store_path`; every additional named output is
retained in the platform entry's `named_outputs` table with its exact
`store_path`, native deployment companion when present, and output-specific
attestation facts. Each output receives its own store-graph and static-cache
root; NAR identities remain in the signed store graph. Preparation fails closed on a missing,
duplicate, or mismatched output binding.

Recipes can also export named outputs as ordinary installable subpackages.
An adjacent `_outputs.nix` declares the source recipe and installable names;
the recipe imports that declaration into `outputPackages` and supplies each
output's runtime dependencies, documentation metadata, module, and qualification
probe. Structural discovery reads the names before resolving recipe arguments,
so consumers can depend on the subpackages through the normal package set.
Names share the package namespace and collisions fail evaluation.

For example, the `aos` recipe exports `apm`, `apr`, and `aos-package-runtime`.
Each owns one logical `out` payload backed by the original physical Nix output
of the same `aos` derivation and version. Publication generates independent
deployment, documentation, compatibility, and provenance metadata for those
package identities; it does not copy executable payloads. `apm install apr`
therefore uses ordinary package resolution, and removing it preserves an
installed `apm`. The unrelated Apache Portable Runtime library remains an
ordinary package named `apache-portable-runtime` with its upstream version.
Publishing the source package also publishes its declared subpackages in the
same signed transaction; publishing one subpackage publishes that package.

Before publishing these names into a registry that previously distributed
Apache Portable Runtime as `apr`, publish that library's upstream releases
under `apache-portable-runtime` and remove the old library-only `apr` catalog
from the new registry release. Do not append publisher version `0.1.0` to a
catalog that still advertises library version `1.7.0`: ordinary version
resolution would select the library. Existing signed release tags keep their
historical records; operators migrate library dependency requests and installed
library selections to `apache-portable-runtime` before adopting the new release.

```sh
aos maintain release step finalize-registry \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --transaction registry-transaction.json \
  --prepared-registry /var/lib/aos-release/2026.9.0/registry \
  --container-release final-container/container-release.json \
  --container-signature-input final-container/signature-input.json \
  --result /var/lib/aos-release/2026.9.0/registry-result.json \
  --signer-executable /opt/aos-signers/bin/provider-adapter \
  --registry-key registry-2026=/media/trust/registry-2026.pub \
  --registry-verification-identity provider-registry-slot \
  --git-name "AOS Release" \
  --git-email release@aos.andyl.org \
  --git-unix-seconds 1788436800 \
  --git-offset-minutes 0
```

The generated transaction's optional `support` object states the `[support]`
tables this release writes into `registry.toml`: its own train's entry and,
only from the newest train, the rolling `default`. Both commands derive the
same object from the plan's frozen contract, and the policy digest describes
`registry.toml` after those tables are applied. A contract that names another
train's entry is rejected, so a backport release can only extend its own train.

Omit both container arguments from both commands for a release with no OCI
artifact; preparation removes any prior release's fixed-path sidecar from the
new tree. Supplying only one is invalid. The sidecar definition must be either
the compatibility alias `containerImages.aos` with exactly one planned image
variant, or the preferred
`systems.<planned-variant>.build.containers.aos` identity.

The two public key files contain exact
`<local-alias>:Ed25519:<base64>` trust lines: `andyl` for `andyl/main`, or the
epoch-matched `andyl-experimental` alias for `andyl/experimental`. Their key ids and
provider revisions must be the single-key,
threshold-one Provenance and Registry requirements frozen in the plan. The
single-signature DSSE and Git formats cannot honestly represent a larger
threshold, so the command rejects one rather than counting repeated signatures
outside the signed object.

During preparation, the provider signs the exact provenance DSSE PAE bytes in the
`aos-package-provenance-dsse-v1` SSHSIG namespace. For the commit and tag it
signs Git's exact unsigned object payload in the `git` namespace. The
coordinator verifies request binding, public-material identity, provider
identity, and the SSHSIG cryptographically before accepting each response. It
also checks the provenance trust line against the active, non-revoked
`keys.toml` entry before authoring.

The source registry must be clean at the exact plan base and must not already
contain the release tag. The output, transaction, and result paths must not
exist. Entry authoring may write catalog, documentation, provenance,
transparency, and store-graph files, but may not move a ref. Preparation
atomically installs the complete uncommitted directory. When any planned
destination's profile requires transaction review, `aos maintain release advance` stops
here until an operator accepts the transaction with `--accept-transaction`. Finalization operates
on those reviewed bytes, creates one signed commit and annotated tag, and
generates its static origin surface. Neither command modifies the authoring
ref, a surface object, a channel, or a private key path.

### Generate and sign the static cache

Generate the cache from the finalized isolated registry, not the mutable
authoring clone:

```sh
aos maintain release step finalize-cache \
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

### Publish the downstream toolchain closures

Downstream repositories that take AOS as their only flake input download
their compilers and build tools from this cache instead of rebuilding them.
The [toolchain set](../engineering/downstream/flake-api.md#toolchain-set) in
[`lib/downstream-toolchains.nix`](../../lib/downstream-toolchains.nix) names
those packages: Bazel and its JDK, the C and C++ compiler wrapper with GCC,
binutils, and glibc, LLVM, Rust, Go, Node.js, pnpm, Python, and `protoc`.

No separate publication step exists. Every member is an ordinary public
package, so planning places it in both Linux package cells, `step build`
realizes all of its named outputs, and `step finalize-cache` publishes their
complete runtime closures. The `checks.downstream.toolchain-release` check
keeps that true: it fails when a member is missing from the release package
inventory, is not a public package, has host constraints that exclude a
Linux platform, or sits on a [deferred platform](#prepare-a-plan-request). Deferring a
Linux platform therefore also requires a reviewed decision to stop publishing
downstream toolchains there.

`aarch64-linux` cells are planned from the `x86_64-linux` coordinator with
`crossSystem`. Every `aarch64-linux` flake output uses the same evaluation,
so the published paths are the ones downstream flakes request.

After a publication, prove that a clean machine downloads every toolchain
from the surface that was just published. `toolchain-cache-check` copies only
the toolchain derivation files into an empty store and realizes both
platforms with no local build slots:

```sh
store=$(mktemp -d)
nix run .#toolchain-cache-check -- --realise --store "$store" -- \
  --option substituters https://cdn.aos.staging.andyl.org/andyl/experimental/ \
  --option trusted-public-keys "$CACHE_PUBLIC_KEY"
chmod -R u+w "$store" && rm -rf "$store"
```

Set the substituter to the published surface's cache origin and
`CACHE_PUBLIC_KEY` to the `name:base64` Nix public key that verifies its
narinfo signatures. For the production `andyl/experimental` surface these are
the values in the flake's `nixConfig`. Run the command from the clean source
checkout frozen in the plan, so the embedded derivations are the planned ones.
A failure lists the derivations that would be built; treat it as an
incomplete publication.

### Close and sign the bundle

Before closing the bundle, prepare a reviewed canonical advisory disposition.
It binds the exact plan and SBOM and identifies each public advisory snapshot
used for review. The disposition feeds the `build-integrity` observation that
every profile requires, `build` included. The registry tier decides what an
unresolved advisory means: a production-tier plan (`andyl/main`) requires an
empty `unresolved_advisories` list, so its bundle cannot reach any
destination with an advisory open. A testing-tier plan (`andyl/experimental`
and its epochs) accepts listed unresolved advisories, and the
`sbom-and-advisory-dispositions` observation states how many remain:

```json
{"authority_id":"release-security-review","plan_digest":"sha256:...","reviewed_at":"2026-09-03T13:30:00Z","sbom_digest":"sha256:...","schema_version":"aos.release.advisory-disposition/v1","sources":[{"name":"osv","snapshot":"sha256:..."}],"unresolved_advisories":[]}
```

Run the assembler against the exact build, signed cache, finalized registry,
image, and container outputs:

```sh
aos maintain release step assemble \
  --plan release-plan.json \
  --build-report release-build/evidence/build-report.json \
  --sbom release-build/evidence/sbom.spdx.json \
  --contributor-authorization contributor-authorization.json \
  --advisory-disposition advisory-disposition.json \
  --cache /var/lib/aos-release/2026.9.0/cache \
  --cache-key cache-2026=/media/trust/cache-2026.pub \
  --registry /var/lib/aos-release/2026.9.0/registry \
  --registry-result /var/lib/aos-release/2026.9.0/registry-result.json \
  --image-set /var/lib/aos-release/2026.9.0/x86_64-linux/finalized \
  --image-set /var/lib/aos-release/2026.9.0/aarch64-linux/finalized \
  --container final-container \
  --completed-at 2026-09-03T14:00:00Z \
  --output release-assembled
```

Omit `--container` only when the qualification contract has no applicable
container target. The command verifies every narinfo signature, compressed-file
identity, decompressed NAR hash, and complete reference closure. It copies a
distinct NAR for every planned logical artifact id, verifies registry
finalization identities, checks finalized image sets and the complete OCI graph
against the exact sidecar committed into that registry, and derives the exact
build-phase qualification observation. It emits
`release-assembled/payload/` and
`release-assembled/release-manifest-payload.json` atomically without replacing
an existing path.

The payload includes package NARs, signed narinfos, registry objects,
provenance, source and license material, the SBOM, build evidence, and finalized
Linux image and OCI artifacts. It does not contain `release-plan.json` or
`release-manifest.json`; the finalizer installs the exact plan itself. Links,
aliases, special files, incomplete closures, unresolved advisories, and bytes
that differ from a finalized input stop assembly.

The registry's finalized `HEAD` names the new release commit, but every
publication must keep discovery on the planned base commit until a channel
operation moves it; the compare-and-swap checks require the published default
commit to equal `registry_base_commit`. The assembler therefore retains the
finalized author's `HEAD` as evidence at `evidence/registry-head` and places a
`registry/HEAD` object (`registry/publication-head`) naming the base commit,
which the publication projects to the surface's `HEAD`. Source-inclusive caches
may carry derivation (`.drv`) store paths, and store-path names follow Nix's own
character rules, including the `?` and `=` that fetched source names retain.

Every `package-nar` record must point to its exact signed `narinfo` record with
an `authenticated-by` relationship. Its outbound relationship graph also names
the dependency NARs and their narinfos needed for public closure verification;
qualification downloads that complete transitive graph from the staging
surface's public read-back route.

```sh
aos maintain release step finalize \
  --plan release-plan.json \
  --payload release-assembled/payload \
  --manifest-payload release-assembled/release-manifest-payload.json \
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
the manifest or whole-bundle digest. Publication receipts continue to bind the
separate exact-byte bundle digest.

### Verify a captured bundle offline

Copy the closed bundle, optional journal, and public verification keys to a
machine that does not need Nix, Git, registry, surface, or network access. Then run:

```sh
aos maintain release step verify ./release-bundle \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --journal ./release-journal.jsonl
```

Repeat `--trusted-key KEY_ID=PATH` to satisfy the manifest threshold. The
verifier rejects links, special files, hard-linked artifacts, path escapes,
non-canonical control documents, digest or size mismatches, invalid signatures,
incomplete matrices, and invalid journal transitions, including a destination
published before its `after` prerequisite. It streams artifact
digests, so disk images need not fit in memory.

Use public keys from an independently authenticated source. A key shipped only
inside the bundle it is meant to authenticate is not a trust anchor.

### Construct immutable TUF metadata

Use an independently authenticated, already signed production root. When the
root is a rotation, also supply its predecessor so both old-root and new-root
thresholds are checked. Build the immutable per-release metadata only after the
bundle manifest is final. Each surface keeps its own TUF metadata versions,
so the driver runs this step for the first destination it publishes on each
surface, after `step record` on the production surface:

```sh
aos maintain release step tuf \
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

### Compose the public release record

After the staging-phase report for a production destination is signed, derive
the public release record from the exact evidence that destination's
publication consumes. Every field is copied from the frozen plan, the final
manifest, the signed qualification, and the public report after the same
verification `step publish` performs; nothing is authored.

```sh
aos maintain release step record \
  --to production/candidate \
  --bundle release-final \
  --staging-receipt release-staging-candidate/receipt.json \
  --signed-qualification qualification-candidate-staging/signed-qualification.json \
  --qualification-report qualification-candidate-staging/qualification-report.json \
  --trusted-key manifest-2026=/media/trust/manifest-2026.pub \
  --qualification-key qualification-authority=/media/trust/qualification.pub \
  --output release-record-candidate.json
```

The record (`aos.release-record/v1`) states the release identity and train,
the qualification result, policy, authority, and signing time, every claim
with its required and achieved assurance, the train's support statement from
the plan's contract, provenance digests, and the exact signed qualification
envelope. Pass it to `step tuf --release-record` so the delegated role
authorizes it beside the manifest, and to `step compose-surface
--release-record` so it is served at
`releases/<class>/<version>/release-record.json`. Composition fails closed when
the delegated targets and the supplied record disagree in either direction.
Consumers verify the record through the TUF chain and, independently, through
its embedded signed envelope; a Hub surface renders it only after verifying
that envelope against its trusted qualification keys. Staging destinations
carry no record. A surface serves one record per release: the record composed
for the first production destination published there. A later destination on
the same surface reuses that publication and attaches its own signed
qualification to its journal entry.

### Refresh TUF timestamp metadata

Timestamp renewal cannot add release content or replace a snapshot. Supply the
current signed root and snapshot, independently authenticated root keys, and
exactly the timestamp-role signature threshold:

```sh
aos maintain release step timestamp refresh \
  --to production/stable \
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
provider identity, prior timestamp continuity, and the 48-hour maximum window.
Continuity has three cases:

| Prior timestamp | Snapshot supplied | New timestamp |
| --- | --- | --- |
| None: the surface has never served one | Any authorized snapshot | Version 1 |
| Names the same snapshot | The same snapshot | Version N+1 over that snapshot (renewal) |
| Names an older snapshot | A newer authorized snapshot | Version N+1 over the newer snapshot (a new release on the surface) |

`--version` must be exactly the prior version plus one, and a new snapshot's
version must be greater than the snapshot the prior timestamp names. Any other
combination fails closed. An expired prior timestamp remains cryptographically
verifiable at its recorded issuance instant, so freshness can recover without
resetting the monotonic version. The porcelain uses the new-snapshot case for
every release after the first on a surface; the renewal timer uses the renewal
case. Publish the resulting pointer through the destination surface's
compare-and-swap operation. First atomically compose it with the immutable
registry/cache surface, full verified TUF set, and exact delegated manifest
target:

```sh
aos maintain release step compose-surface \
  --to production/stable \
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
aos maintain release step timestamp publish \
  --to production/stable \
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
`tuf/timestamp.json` and `tuf/41.snapshot.json`. On a Hub surface the
coordinator uploads the surface into an invisible preparing publication, and
the release-scoped Hub RPC atomically reserves the next timestamp version and
exact object identities before it commits the mutable publication pointer. A
lost response is retried with the same publication and evidence; a different
request for the reserved version fails closed. On a static surface the
coordinator replaces `tuf/timestamp.json` with the surface's
[compare-and-swap](release-static-surfaces.md#static-surfaces). The coordinator then performs full anonymous public
read-back and preserves the timestamp plus publication evidence without
replacing an existing output.

### Bootstrap the first registry base

A new staging or production surface has no publication that can serve as the
compare-and-swap parent of its first release. Do not let the first release
self-authorize that base. Obtain identical
`aos.release.registry-bootstrap-intent/v1` envelopes signed by exactly the
plan's `release-evidence` threshold. The intent binds the environment,
surface identity, the plan's exact registry identity, planned base commit, plan
digest, public authority, and approval time.

A registry's first release runs in this order:

1. Create the registry on each surface without publishing anything: the
   reviewed `aos hub registry create` plan and apply on a Hub, or the
   `.aos-surface` identity on a static origin.
2. Plan with
   [`new --first-release --source-registry`](release-commands.md#plan-a-registrys-first-release).
   Note the printed plan digest and the base commit in the `Registry` row.
3. Write one intent payload per environment. Every approver signs the same
   bytes, so `authority_id` names the approving authority rather than one key,
   and `approved_at` is fixed before signing:

   ```json
   {
     "schema_version": "aos.release.registry-bootstrap-intent/v1",
     "environment": "staging",
     "deployment_id": "staging-2026-09",
     "registry": "andyl/experimental",
     "base_commit": "<registry_base_commit from plan.json>",
     "plan_digest": "sha256:<SHA-256 of plan.json>",
     "authority_id": "andyl-release-evidence",
     "approved_at": "2026-10-02T12:00:00Z"
   }
   ```

   Each release-evidence key holder signs it, for example with
   `aos-release-signer sign-evidence --key-id release-evidence-v1
   --payload staging-intent.json --output approvals/staging-bootstrap-1.json`.
4. Export the clone's root commit as a static registry surface:
   `apr origin upload --registry andyl-experimental --upload-url
   file:///var/lib/aos-release-coordinator/base-registry-surface`.
5. Run `step bootstrap` for staging, then for production, as below.
6. Place the clean clone at `<work>/inputs/source-registry/` and continue
   with `aos maintain release advance --to staging/<channel>`.

Install the reviewed base in staging first:

```sh
aos maintain release step bootstrap \
  --plan "$WORK/plan.json" \
  --registry-surface base-registry-surface \
  --environment staging \
  --signed-intent approvals/staging-bootstrap-1.json \
  --signed-intent approvals/staging-bootstrap-2.json \
  --approval-key evidence-1=/media/keys/evidence-1.pub \
  --approval-key evidence-2=/media/keys/evidence-2.pub \
  --config /etc/aos-release/maintainer.toml \
  --output "$WORK/bootstrap/staging"
```

Repeat with independent production intent envelopes, the production
credentials, `--environment production`, and
`--output "$WORK/bootstrap/production"`. `advance` reads exactly these output
directories: it refuses one that lacks `bootstrap-evidence.json` or records
another environment or base commit. A Hub surface takes `--token` or
`AOS_TOKEN`, else, with `--config`, the configuration's `token_credential`,
else the active `aos hub login` profile for its origin
([Hub credentials](release-maintainer-machine.md#hub-credentials)); a static surface's upload credentials
come from the maintainer configuration named by `--config`.
The command dispatches on the plan's surface kind: it uses the Hub publication
protocol for a Hub surface and writes the base surface, with its registry head
object, directly to a static origin whose `.aos-surface` already names the
planned identity. The command
refuses a destination containing any publication, requires the resulting first
publication to have no parent, checks its default commit against the plan,
pins the surface identity before and after upload, and performs
complete and ranged public read-back. Preserve the emitted bootstrap evidence;
all later release publications use this base publication as their explicit
parent. Bootstrap is not a recurring release step.

### Publish to a destination

`step publish` places the exact finalized bundle on one destination's surface.
It dispatches on the plan's surface kind: the Hub publication protocol for a
`hub` surface, direct upload for a [static surface](release-static-surfaces.md#static-surfaces). Staging:

```sh
aos maintain release step publish \
  --to staging/candidate \
  --bundle release-bundle \
  --journal release-bundle/release-journal.jsonl \
  --surface staging-candidate-surface \
  --trusted-root-key root-2026=/media/keys/root-2026.pub \
  --trusted-root-threshold 1 \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --output release-staging-candidate
```

Production additionally requires the staging receipt, the destination's signed
staging-phase qualification, and the fitness attestations its profile names:

```sh
aos maintain release step publish \
  --to production/candidate \
  --bundle release-bundle \
  --journal release-staging-candidate/release-journal.jsonl \
  --surface production-candidate-surface \
  --trusted-root-key root-2026=/media/keys/root-2026.pub \
  --trusted-root-threshold 1 \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --predecessor-receipt release-staging-candidate/receipt.json \
  --predecessor-receipt-key staging-hub-2026=/media/keys/staging-hub-2026.pub \
  --evidence qualification-candidate-staging \
  --qualification-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --fitness /var/lib/aos-release-coordinator/fitness \
  --output release-production-candidate
```

A staging destination's `build` profile requires no qualification evidence,
predecessor receipt, review, or fitness attestation: `step publish --to
staging/<channel>` rejects `--evidence` and `--predecessor-receipt`. Everything
else still applies. The build's repeat-build and deriver checks, the
advisory disposition, and the `build-integrity` observations are required for
every destination, and every publication, staging included, is read back
anonymously in full.

`--surface` is the destination's composed surface from [`step
compose-surface`](#refresh-tuf-timestamp-metadata), which carries the TUF
metadata and, for a production destination, the release record. It requires
the independently trusted `--trusted-root-key KEY_ID=PATH` values and their
`--trusted-root-threshold` (default 2). Before anything is uploaded, the
surface's snapshot (or its timestamp, when present), root, targets, and
release-class delegation must keep the plan's frozen signer policy and verify
against those root keys, and the delegated target must bind this bundle's
manifest envelope. The published surface is then exactly the projected bundle
plus those verified additions: the TUF metadata files, the public manifest
(identical to the bundle's envelope), and the release record only when the
delegated target authorizes its exact digest and length. Any other composed
file must be byte-identical to the projected object at its path; an extra,
changed, or missing verified file fails the command. Fitness is
checked against the attestations under `--fitness DIR` and the live binding
values given by `--tooling-digest`, `--alert-config-digest`, and
`--hub-schema`. Explicit flags win; otherwise the maintainer configuration
named by `--config` supplies `fitness_root` and the live values, which is how
the porcelain calls the command. A Hub surface takes a short-lived token for
that surface only, through `--token` or `AOS_TOKEN`, or the configuration's
`token_credential`; without either, it uses the approved `aos hub` login
profile for that origin, whose credentials are refreshed before each object or
multipart operation of a long upload. An explicit token's lifetime remains the
caller's responsibility. A static surface resolves
its upload credentials and the `surface-receipt` signer from the maintainer
configuration named by `--config`, with the same default search as the
porcelain. Keep staging and production credentials in different operator steps.

Before any upload, the command verifies the complete bundle, signature
threshold, and journal: the release must be `finalized` and every surface role
in the destination's `after` list must already be published. For a production
destination it verifies the staging receipt, the signed qualification against
its independent key, that the qualification covers exactly the destination's
planned gates under the recomputed change scope, that every required review is
present, and that every required fitness attestation is fresh and matches the
live bindings.

The command checks the surface identity before and after upload, reads every
committed object back anonymously through the public read-back route, and
compares its exact SHA-256 and size, including exact prefix and suffix byte
ranges where the origin is HTTP. The receipt is verified with an independently
pinned surface receipt key rather than a release-manifest key. On a production
Hub, the surface also verifies and imports the signed staging and
qualification envelopes and binds them to its publication. A surface that
already holds this release's publication for another destination is verified
by full read-back instead of a second upload.

The output contains the destination's `receipt.json` and a successor
`release-journal.jsonl` with a `published` entry for the destination. A
production entry carries the digests of the admitted qualification evidence;
there is no separate qualified state. Existing paths are never replaced.

### Run the native qualification matrix

Configure absolute executable paths for the applicable platforms. The Linux paths invoke Linux
test closures. The Darwin paths are credential-free authenticated remote
adapters whose far ends execute on supported Intel and Apple Silicon macOS.
Release-wide cases use the x86_64 Linux executor. Image and container cases
select their declared reference target; package cases select each published
package/platform independently. An absent unrelated platform requires no
adapter. The destination's profile and the plan's change scope select the
cases.

Each adapter reads one canonical request from standard input and writes one
canonical `aos.release.qualification-executor-response/v1` object to standard
output. Successful adapters must not write diagnostics. They download every
object they exercise from the anonymous URLs in the request and verify the
declared length and SHA-256 before testing it. Image update requests also
carry a separate inventory of exact objects from the locally retained,
offline-verified predecessor bundle. The executor recaptures those files into
its private attempt directory and checks their lengths and hashes before the
image scenario can use them.

Run `aos maintain release step qualification cases --to <destination>` first and retain its
`environment_profile_digests`. Review the compatibility scope and sources for
each required target, then install the canonical assessment object as
`/etc/aos-release/qualification-assessments/<target-id>.json` on the applicable
Linux executor host. The built-in container lifecycle program refuses a
missing, symlinked, or scope-mismatched assessment and records its own concrete
execution inventory. Run the `release-tooling` closure that ships the
matching executor rather than copying an individual scenario script without
its closure.

```sh
aos maintain release step qualify-run \
  --to production/candidate \
  --phase staging \
  --bundle release-bundle \
  --staging-receipt release-staging-candidate/receipt.json \
  --predecessor-bundle /srv/aos-release/qualification-snapshot/bundle \
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
  --qualified-at now \
  --prepare-only \
  --output qualification-prepared
```

Both nonce values are single-use operator inputs. The plan must name a distinct
`qualification` signer role with exactly the public key supplied above. The
predecessor bundle path must be absolute. `qualify-run` verifies its complete
signed closure against `--trusted-key` and the plan's exact predecessor
registry, release ID, and manifest digest before starting any executor. Supply
it while collecting observations; omit it when admitting a reviewed report
with `--report-input`. The collection command retains each machine-readable
executor report and the canonical aggregate report. Review those exact bytes,
then repeat the command with
`--report-input qualification-prepared/qualification-report.json`,
`--review-receipt approvals/review.json`, and `--output qualification`, omitting
`--prepare-only`. Repeat review receipts to satisfy the destination's review
threshold. The staging phase always reads the staging surface; rollout and
complete phases read the destination's surface through
`--publication-receipt`, the alias of `--staging-receipt`, with that surface's
receipt key in `--hub-receipt-key`. A rollout run adds `--ring N`,
`--prior-generation G`, and `--journal`; a complete run adds `--journal`.
The [shared qualification guide](qualification-results.md#collect-review-and-sign)
specifies the review payload and later hold points. Missing applicable adapters
fail closed. `--qualified-at now` resolves after collection, avoiding a receipt
time earlier than the tests it authorizes.

### Advance a planned channel ring

Advance only a ring frozen in the plan's destination, using the exact
generation observed by the operator. Rings are numbered from 1 in profile
order; ring `N` covers the partitions after ring `N-1`'s cumulative count up to
its own. When the profile has a rollout gate, first collect and sign a
`rollout` report for that ring against the destination's publication receipt
and current journal, as specified in
[the shared guide](qualification-results.md#collect-review-and-sign):

```sh
aos maintain release step channel advance \
  --to production/stable \
  --ring 2 \
  --prior-generation 7 \
  --qualification qualification-stable-rollout-2 \
  --qualification-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --bundle release-bundle \
  --journal release-stable-ring-1/release-journal.jsonl \
  --publication-receipt release-production-stable/receipt.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --channel-receipt-key channel-2026=/media/keys/channel-2026.pub \
  --output release-stable-ring-2
```

Omit `--qualification` and `--qualification-key` for a destination whose
profile has no rollout gate (`build` and `smoke`). Pass each earlier ring's
channel receipt of the destination with a repeated `--channel-receipt`. On a
static surface `--prior-generation` may be omitted, and the command reads the
current generation record instead. The command takes the same fitness inputs
as `step publish`, plus `--token` for a Hub surface or `--config` for a static
one. It works for staging and production destinations and for both surface
kinds. The previous ring's `observe_seconds` must have elapsed since its
channel receipt. On a destination whose profile selects no `qualified` claims,
the final ring's advance also records the destination `complete`.

On a Hub surface the Hub commits the generation evidence, channel frontier, and
every selected partition in one transaction; a staging Hub accepts the advance
once it holds the release's staging publication, and a production Hub requires
its production publication. The channel must already exist on the Hub as an
indexed channel; see [channels and receipts](release-static-surfaces.md#channels-and-receipts). On a
static surface the command performs the [compare-and-swap](release-static-surfaces.md#static-surfaces)
itself. A stale generation, missing publication, altered public projection,
stale health approval, or ring outside the plan fails closed. The command
verifies the publication receipt through the anonymous route before mutation,
verifies the signed channel receipt afterward, reads every selected public
partition back, and appends a `rolling` journal entry for the destination.
Later rings append `rolling`-to-`rolling` entries with their own generations
and receipts. For a `soak` destination, closing the rollout is a separate
retention and handoff decision.

### Complete a rollout

After every planned ring has advanced, obtain identical completion decisions
signed by exactly the `release-evidence` threshold frozen in the plan. Each
canonical decision uses schema `aos.release.completion-receipt/v1` and binds the
release, plan, manifest, the destination's publication receipt, the sorted
digest of every channel receipt, the exact rolling journal-head digest, the
frozen retention policy, affirmative corresponding-source retention,
affirmative operational handoff, a public authority identity, and an RFC 3339
UTC completion time. `aos maintain release review` produces one such decision per
reviewer.

When the destination's profile has a complete gate (`soak`), collect and sign
the `complete` observation report after the soak, using the publication receipt
and current rolling journal. Then recheck the complete public rollout and close
the destination:

```sh
aos maintain release step channel complete \
  --to production/stable \
  --qualification qualification-stable-complete \
  --qualification-key qualifier-2026=/media/keys/qualifier-2026.pub \
  --bundle release-bundle \
  --journal release-stable-ring-4/release-journal.jsonl \
  --publication-receipt release-production-stable/receipt.json \
  --channel-receipt release-stable-ring-1/channel-receipt.json \
  --channel-receipt release-stable-ring-2/channel-receipt.json \
  --channel-receipt release-stable-ring-3/channel-receipt.json \
  --channel-receipt release-stable-ring-4/channel-receipt.json \
  --completion-receipt approvals/completion-release-evidence-1.json \
  --completion-receipt approvals/completion-release-evidence-2.json \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --receipt-key production-hub-2026=/media/keys/production-hub-2026.pub \
  --channel-receipt-key channel-2026=/media/keys/channel-2026.pub \
  --completion-key evidence-1=/media/keys/evidence-1.pub \
  --completion-key evidence-2=/media/keys/evidence-2.pub \
  --output release-stable-complete
```

Only a destination whose profile selects `qualified` claims (`soak`) runs
this command; every other destination is already `complete` after its final
ring. The
command accepts no access token and performs no surface mutation. It verifies
one signed channel receipt for every planned ring, proves each receipt is
already part of the rolling journal, rejects gaps in the destination's
generations, checks the anonymous publication receipt and all public
partitions, and verifies that every completion signer approved identical
bytes. The output retains all receipts and appends the destination's sole
`rolling`-to-`complete` transition without replacing an existing path.

### Inspect a captured journal

Inspect any copied journal without initializing Nix or reaching a surface:

```sh
aos maintain release step status --journal release-stable-complete/release-journal.jsonl --plan plan.json
```

The command verifies the hash chain and every transition, then prints the
global state and each destination's state. With `--plan`, it also lists the
planned destinations that are not yet published.
