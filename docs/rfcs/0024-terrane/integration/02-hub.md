# 02 — AOS Hub storage on Terrane

This file describes how AOS Hub stores and serves registry content through
Terrane: R2 (or S3) as the bucket backend, one Terrane view per registry, the
`nix-cache`, `oci`, `browse`, and `api` surfaces as the Hub's public storage
endpoints, and the Cloudflare Worker as a `terrane-edge` instance. It states
what stays in `aos-hub` and how existing SHA-256 keys keep resolving.

Requirement IDs use the prefix `HUB`. Relevant Hub RFCs: RFC-0004 (registry
hub), RFC-0012 (surface topology, retention, and GC), RFC-0023 (hybrid
runtime topology: Worker edge in front of a native Hub on GCP, storage-work
API over R2).

## What changes and what does not

| Hub concern | Today | With Terrane |
| --- | --- | --- |
| Object bytes (NARs, OCI blobs, images) | Whole objects in R2 keyed by SHA-256 | Chunks in packs under `objects/pack/`, one bucket per Hub deployment (spec `13-bucket-layout.md`) |
| Registry namespace | PostgreSQL rows plus R2 keys | One branch per registry, `refs/heads/<org>/<project>/<registry>`, a tree with `nix/`, `oci/`, `images/` roots |
| Nix binary cache HTTP | `aos-hub` and Worker handlers | `nix-cache` surface (spec NIX-1 to NIX-13) over the registry view |
| OCI Distribution | `aos-oci` handlers, R2 staging | `oci` surface (spec OCI-1 to OCI-7) |
| Console reads | Connect handlers over PostgreSQL and R2 | `api` surface (WEB-6) plus `browse` for listings; commit history, diffs, and blame from the tree |
| Retention and GC (RFC-0012 §04) | Hub GC controller over R2 listings | Terrane mark-and-sweep from registry refs, retention as root properties (spec GC-1, GC-28) |
| Identity, tenancy, IAM, signing, publication policy | `aos-hub-core` | Unchanged; issues Terrane capability tokens |
| Storage-work API (RFC-0023) | Worker executor over R2 bindings | Terrane tree jobs (spec `32-tree-jobs.md`) invoked by native, executed at the edge where bounded, or natively |

- **[HUB-1]** `aos-hub-core` MUST remain the authority for organizations,
  projects, registries, principals, roles, and publication policy (RFC-0004
  `02-tenancy-iam-auth.md`). It MUST act as a Terrane token issuer (spec
  AUTH-3, AUTH-13), mapping Hub permissions to grants on registry refs and
  roots, and MUST NOT store object bytes or namespace state of its own.
  *Gate:* `checks.terrane.integration.hub-issuer`.
- **[HUB-2]** Every registry MUST be one Terrane branch under a
  deployment-wide tenant prefix, with `acl`, `domain`, `retain`, and `trust`
  properties (spec `08-properties.md`) set from the registry's Hub
  configuration by a reconciler in `aos-hub`. The Hub configuration is the
  source of those properties; the tree is where they take effect. *Gate:*
  `checks.terrane.integration.hub-registry-branch`.

## R2 as a bucket

RFC-0023 already assumes the Worker serves bulk bytes from R2 or S3 bindings.
Spec BKT-10 requires a startup probe of conditional writes; R2 supports
`onlyIf` on the Workers binding and `If-Match` / `If-None-Match` on its S3
API, so the ref protocol runs unchanged.

- **[HUB-3]** A Hub deployment MUST configure exactly one Terrane bucket per
  Hub authority, shared by the native service and the Worker (spec EDGE-14),
  with refs homed at the native service's region (spec REF-30). *Gate:*
  `checks.terrane.gates.edge-native-interop`.
- **[HUB-4]** The Worker MUST run `terrane-edge` as the storage half of the
  RFC-0023 public edge: reads, presigned bulk reads (spec EDGE-5),
  zero-CPU `.nar.zst` streaming (EDGE-6), token verification (EDGE-7), and
  small commits from clients that chunked locally (EDGE-8). Large merges,
  GC, compaction, and imports MUST run natively (EDGE-11, EDGE-12). *Gate:*
  `checks.terrane.integration.hub-edge-role`.
- **[HUB-5]** `aos-hub-core`'s pure SigV4 signer (`sigv4.rs`) and presigned
  URL bindings (`s3surface.rs`) SHOULD be moved into, or re-exported from,
  the `terrane` bucket backend rather than duplicated. `aos-net`'s S3 SDK,
  multipart, and resumable download code SHOULD back the native `bucket`
  backend's `HttpClient` implementation. *Gate:* `checks.terrane.gates.crate-graph`
  (no duplicate signer).

## SHA-256 continuity

Existing Hub clients, `apr`, `apm`, and `aos-cache` address NARs and OCI
blobs by SHA-256. Terrane's identity is BLAKE3, and SHA-256 is a derived
attribute with an index tree (spec DRV-6, DRV-12, NIX-9, REAPI-2, OCI-4).

- **[HUB-6]** Every registry root MUST set `hashes = [blake3, sha256]` and
  `index = [hash.sha256, nar.store_path_hash]` so that every existing key
  resolves by one index lookup. *Gate:*
  `checks.terrane.integration.hub-sha256-index`.
- **[HUB-7]** The initial migration MUST use the `nix-binary-cache` and `oci`
  import adapters (spec MIG-5) on a job branch per registry, verify by
  recomputing SHA-256 against the Hub's existing records (MIG-7), and cut
  each registry over with one ref write after the Hub's reconciler confirms
  completeness (spec PROP-23) is 100%. Rollback is the reverse ref write
  (MIG-32). *Gate:* `checks.terrane.integration.hub-import`.

## Surfaces the Hub exposes

```toml
[[expose]]
view    = "refs/heads/andyl/aos/testing:/nix"
surface = "nix-cache"
at      = "https://hub.example/andyl/aos/testing/nix"

[[expose]]
view    = "refs/heads/andyl/aos/testing:/oci"
surface = "oci"
at      = "https://hub.example/v2/andyl/aos/testing"

[[expose]]
view    = "refs/heads/andyl/aos/testing"
surface = "browse"
at      = "https://hub.example/andyl/aos/testing/tree"

[[expose]]
view    = "refs/heads/andyl/aos/testing"
surface = "api"
at      = "https://hub.example/api/terrane"
```

- **[HUB-8]** Registry signing (`aos-hub-core/src/nix_sign.rs`) MUST
  continue to produce narinfo signatures; the `nix-cache` surface serves them
  verbatim from `nar.signatures` (spec NIX-8). Signing happens at publication
  time as a tree job that annotates entries (spec JOB-14) under the Hub's
  signing identity, never inside the surface. *Gate:*
  `checks.terrane.integration.hub-signing`.
- **[HUB-9]** The Hub console (`aos-hub-console`) MUST read tree listings,
  commit history, diffs, and per-property completeness through the `api`
  surface only (spec WEB-4, WEB-6). No console endpoint may read the bucket
  directly. *Gate:* `checks.terrane.integration.hub-console-api`.
- **[HUB-10]** OCI publication (RFC-0019) MUST target the `oci` surface's
  layout (`oci/blobs`, `oci/manifests`, tags as symlinks; spec OCI-1, OCI-2)
  and MUST rely on OCI-3's manifest-time completeness check in place of the
  Hub's R2 staging checks. *Gate:* `checks.terrane.integration.hub-oci`.

## Retention and garbage collection

RFC-0012 `04-retention-and-gc.md` defines per-registry retention over R2
listings. With Terrane, retention is a `retain` property per root (spec
PROP-9, GC-28), snapshots are tags (REF-19), and collection is mark-and-sweep
from refs with a grace window (GC-10).

- **[HUB-11]** The Hub GC controller (`aos-hub-core/src/gc_controller.rs`)
  MUST become a driver of Terrane's collector: it sets `retain` properties
  and tags releases; it MUST NOT delete bucket keys itself. Only the singleton
  Terrane collector (GC-22) sweeps. *Gate:* `checks.terrane.integration.hub-gc`.
- **[HUB-12]** Channels and signed releases (RFC-0017) MUST be tags, so a
  published release is immutable by construction (spec REF-19) and remains a
  GC root while its tag exists. *Gate:* `checks.terrane.integration.hub-tags`.

## Client crates

- **[HUB-13]** `aos-cache` remains the Nix-compatible transfer client. It
  MAY gain a `terrane://` backend that speaks the wire protocol for
  negotiation and presigned reads (spec BW-1 to BW-7), and MUST keep its
  `http(s)` and `s3` backends working against the `nix-cache` surface
  unchanged. *Gate:* `checks.terrane.integration.hub-client-compat`.
- **[HUB-14]** `apr` and `apm` MUST NOT require Terrane awareness for reads;
  their existing binary-cache protocol use is served by the surface. Writers
  that want chunk-level dedup on upload use the SDK. *Gate:*
  `checks.terrane.integration.hub-client-compat`.

## Interactions

- Spec files `13`, `18`, `30`, `32`, `33`, `38`.
- [`03-packaging.md`](03-packaging.md) for the Worker build.
- [`05-implementation-plan.md`](05-implementation-plan.md) Phase 6.
- [`06-decision-register.md`](06-decision-register.md) AD-3 (adoption order).
