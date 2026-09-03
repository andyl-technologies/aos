# Canonical release coordinator

Canonical AOS releases are driven by one reviewed plan. The plan freezes the
source revision, registry base, complete package and image matrices, required
gates, signer roles, deployment identities, intended channels, and retention
policy before a build or signing effect occurs.

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
- `aos release status` reconciles a captured journal without Nix or network;
- `aos release stage` accepts only an already finalized signed bundle, pins the
  canonical staging deployment identity before and after upload, reuses the
  bounded Hub publication protocol, reads every object back anonymously, and
  writes a staging receipt plus successor journal;
- `aos release verify` checks a closed release bundle and optional journal
  offline against explicitly supplied public keys.

Registry-to-bundle finalization, qualification, release-scoped Hub admission,
production promotion, TUF freshness, and channel commands
remain incomplete. The current staging command is therefore an M1 transport
edge for non-production package bundles only; it is intentionally unreachable
until another implementation has produced a valid `Finalized` journal entry.
Production publication through this workflow remains forbidden.

The canonical release image profile enables external Secure Boot, distinct
module and PCR-policy roles, lockdown, measured boot, encrypted state,
dm-verity, signed recovery, audit, firewalling, and the hardened runtime
preset. It deliberately reports SELinux as excluded: the current immutable
root is not pre-labeled, so enabling the existing policy would overstate the
MAC boundary. SELinux may enter the production profile only with labeled-root
construction and an enforcing boot qualification gate.

## Prepare a plan request

Create a reviewed JSON object with schema
`aos.release.plan-request/v1`. Unknown and duplicate fields are rejected. The
request supplies:

- release id, calendar version, and release class;
- the canonical `andyl/main` registry and its exact base commit and generation;
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

## Stage a finalized M1 bundle

The staging command always targets `https://aos.staging.andyl.org`; it has no
production URL option. Supply a short-lived staging-only token and the public
manifest keys:

```sh
aos release stage \
  --bundle release-bundle \
  --journal release-bundle/release-journal.jsonl \
  --trusted-key release-2026=/media/keys/release-2026.pub \
  --output release-staging
```

Before any upload, the command verifies the complete bundle, signature
threshold, and exact `Finalized` journal precondition. It checks the public
deployment identity before and after upload, reads every committed object back
anonymously through the public registry route, and compares its exact SHA-256
and size. The new directory contains `staging-receipt.json` and a successor
`release-journal.jsonl`; existing paths are never replaced.

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

## Operational boundary

Do not emulate missing later phases with ad hoc repeated package publishes,
manual object copies, mutable tags, or direct channel edits. RFC-0017 requires
one isolated registry transaction, role-separated signing, exact-byte staging
and promotion receipts, production read-back, and compare-and-swap channel
updates. Those operations remain fail-closed until their command implementations
and qualification gates land.

The normative design and rollout requirements are in
[RFC-0017](../rfcs/0017-canonical-hub-publishing/README.md).
