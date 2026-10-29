# Distribution and publication

## Shared wire contract

`aos-oci-types` is the dependency-light boundary shared by the CLI, native Hub,
Cloudflare Worker, and browser console. It performs no I/O and compiles for
`wasm32-unknown-unknown`. Registries retain and digest the exact bytes they
receive; the crate's types are bounded projections used for admission, graph
traversal, and AOS-generated canonical JSON, and never replace an uploaded
body.

### Media types

`media_type.rs` is an exact allowlist, matched without parameters or case
folding:

- OCI image manifest, index, and config, and uncompressed, gzip, and zstd OCI
  layers (the AOS builder emits gzip);
- Docker schema 2 manifest, manifest list, config, and uncompressed and gzip
  layers (Docker schema 1 is rejected);
- `application/octet-stream`, only as the storage type of an upload that no
  manifest has admitted yet;
- `application/vnd.oci.empty.v1+json`, whose only accepted body is `{}`, used as
  the artifact config;
- AOS artifacts: `application/vnd.aos.container-release.v1+json`,
  `application/vnd.aos.container.static-abilities.v1+json`,
  `application/vnd.aos.nix-closure.v1+json`,
  `application/vnd.aos.source-closure.v1+json`,
  `application/vnd.aos.source-closure.v1.tar+gzip`, and
  `application/vnd.aos.license-report.v1+json`;
- `application/spdx+json`, `application/vnd.in-toto+json`, and
  `application/vnd.dsse.envelope.v1+json`.

Adding a media type is a compatibility change that needs parser, runtime,
storage, and GC coverage.

An artifact is an OCI image manifest with a required `artifactType` and
`subject`, the empty config, and payload layers. A JSON artifact has exactly
one payload layer matching its `artifactType`. A source-closure artifact has
two ordered layers: the JSON inventory, then the gzip source archive.
Descriptors with external URLs and artifact indexes are rejected.

### Admission limits

`limits.rs` fixes the structural limits applied before allocation or traversal.
Deployments may lower operational byte limits but cannot raise these without a
compatibility review, because every parser relies on the same bounds.

| Limit | Value |
|---|---:|
| Manifest, index, config, or artifact JSON | 4 MiB |
| Descriptors in one manifest or index | 1,024 |
| Platforms in one index | 256 |
| Layers in one runnable image | 64 |
| Descriptor graph depth | 8 |
| Reachable descriptors in one publication | 65,536 |
| Annotation key / value / total per object | 1 KiB / 4 KiB / 64 KiB |
| Repository name | 255 bytes |
| Tag | 128 bytes |
| Upload session lifetime | 24 hours |

Blob sizes are bounded by registry quota and a deployment maximum with checked
64-bit arithmetic.

### Canonical references

`reference.rs` and `digest.rs` accept values byte for byte or reject them. They
never lowercase, trim, percent-decode, collapse separators, or fall back from
one interpretation to another.

- A repository is one or more slash-separated lowercase components, at most 255
  bytes. Each component starts and ends with `[a-z0-9]`; separators inside a
  component are `.`, `_`, `__`, or one or more `-`.
- A tag matches `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` and is case-sensitive.
- A digest is exactly `sha256:` and 64 lowercase hex digits; SHA-256 is the
  only algorithm.
- Percent-encoded octets are rejected in repository names, tags, and digests.
- A manifest reference is either a tag or a digest, never a fallback after a
  failed parse.

Hub's raw-path router locates the fixed `/v2/`, `/blobs/`, `/manifests/`,
`/tags/list`, and `/referrers/` separators and hands the exact repository bytes
to this parser. Authorization compares the same bytes, without case folding or
decoding.

Protocol errors use the standard Distribution codes (`distribution.rs`), with
AOS detail in bounded message and detail fields.

## Hub data plane

Every OCI repository belongs to one AOS registry and inherits its tenant,
authorization, placements, quota, signed releases, and audit boundary. Each
registry has one OCI delivery authority, a Hub-provided wildcard name or a
custom domain, and the authority is resolved to the registry before `/v2/`
routing begins. Repository names are local to that registry, so equal names in
different registries never collide.

The bearer challenge names the authority as the token service and requests
`repository:<name>:<actions>`. Token exchange turns an authenticated Hub
identity into a short-lived token for that exact service, repository, and
action set; public pull may be anonymous. Private requests authorize the exact
repository before any tag, manifest, or blob lookup, so a caller cannot probe
registry-wide content-addressed bytes by digest. A cross-repository mount
requires pull on the source and push on the destination.

All OCI objects, including manifests and indexes, are immutable blobs under
`oci/blobs/sha256/<digest>` in the registry's object store, and manifest bytes
are served exactly as uploaded. Tags are database pointers with append-only
history. Quota is charged once per registry digest: linking an existing blob
into another repository changes reachability, not stored-byte usage.

The individual Distribution capabilities (pull, push, verified publication,
administration, and GC) are server-side gates; the
[user guide](../../users/aos-hub/oci-containers.md#rollout-gates) lists their
flags.

## Verified publication

Signing and OCI transfer are separate steps, and no AOS command reads a private
key:

1. Nix emits the unsigned `publicationInputs` graph and its
   `signature-input.json`.
2. `aos container prepare-signature` writes the exact DSSE PAE bytes; the
   operator signs them externally with SSHSIG namespace
   `aos-container-signature-dsse-v1`.
3. `aos container finalize-signature` verifies the signer identity, namespace,
   and exact bytes, validates the qualified graph, and atomically creates a
   bundle containing `layout/`, `image.oci.tar`, `container-release.json`, and
   `signature-input.json`.
4. The release transaction commits the `container-release.json` sidecar into
   the signed package release (`aos release prepare-registry
   --container-release ...`), and `aos container publish --stage-only` uploads
   the immutable graph into the registry candidate without moving a tag.
5. After Hub indexes and authenticates the signed release, `aos container
   publish` re-uploads idempotently and commits through the Hub control plane,
   which advances the tag and marks the root verified.

The sidecar (`release.rs`, strict and rejecting unknown fields) binds the
package release, the logical container name, the OCI index and per-platform
manifest descriptors, Nix definition and output provenance, static ability
evidence, and the closure, SBOM, source, license, provenance, and signature
referrer descriptors. The sidecar is schema version 2 and the signature input
is `aos.container.signature-input/v2`; both readers reject any other version.
The sidecar carries no completeness field: the Nix referrer build fails unless
every runtime closure path maps to one package with retained corresponding
source and license metadata, so a sidecar exists only for a complete closure.

A generic Distribution push can create an unverified manual tag but never a
verified release root. The operator procedure is in the
[canonical release runbook](../../maintainers/canonical-releases.md).

## Garbage collection

OCI GC (`aos-hub-db/src/db/oci_gc/`, `aos-hub-service/src/oci_gc_controller.rs`)
is a fail-closed, reviewed mark and sweep:

1. A run freezes the registry root set (tags, signed release roots, retained
   referrers, leases, and active uploads), the retention policy,
   provider-enumerated inventories, and every placement capability.
2. Planning traverses every descriptor edge, applies the grace period, and
   produces a reviewable deletion plan. Missing edges or stale inventory abort
   the run.
3. Applying the plan tombstones all candidates atomically.
4. Provider workers delete each exact placement under digest, size, and etag
   preconditions. The database claim rechecks the run, roots, topology, and
   capabilities immediately before provider I/O.
5. Catalog identity and quota are released only after every frozen placement
   confirms deletion or absence.

Retention policy (untagged grace, deleted-tag history, recent manual
revisions, and referrer retention) is edited through the same reviewed
plan-and-apply flow in the Hub console and `aos hub registry container`.
