# 01 — Sandbox runtime integration (RFC-0021)

This file maps Terrane onto the slots RFC-0021 leaves open in the sandbox
runtime: the unprivileged view service, the networkless publisher, per-view
FUSE workers, the privileged mount broker, attachments, disclosure domains,
and the portable-object descriptor profile. It names what Terrane satisfies
unchanged, what it changes, and what RFC-0021 keeps owning. The RFC-0021
text referenced here is the version on branch
`dplecki/sandbox-filesystem-views-rfc` (PR #232).

Requirement IDs in this file use the prefix `SBX`. Gates are AOS checks named
in [`03-packaging.md`](03-packaging.md) §checks.

## The seam RFC-0021 already reserves

RFC-0021 `02-architecture.md` specifies an unprivileged `aos-viewd` that owns
source adapters, validation of untrusted trees, portable tree storage,
compiled node-local indexes, verified immutable backing objects, cache
admission, pins, eviction, scrub, prefetch, and supervision of FUSE workers.
It specifies a separate, networkless `aos-view-publisher` that alone owns the
committed portable-object, index, and backing roots and seals them with
fs-verity. It specifies per-view FUSE workers with no network that request
backing handles from the view service and passthrough registration from the
mount broker. Its crate plan (`14-implementation-plan.md` §Rust ownership)
names a future `aos-sandbox-view` crate for "portable-tree compiler, isolated
publisher, FUSE worker, view/cache client". None of those exist as code.

In the RFC-0021 worktree, `crates/aos-filesystem-view-core` carries two
dormant traits that were written for exactly this integration:

- `ObjectSource` (`src/source.rs`): open one portable object as a bounded,
  non-buffering byte stream by exact descriptor; the caller verifies length
  and digest.
- `ImmutableFetchTransport` and `FetchControl` (`src/remote_source.rs`):
  bounded, resumable, ambiguity-aware fetch of an immutable object. The
  module header says "No concrete network client, endpoint, credential
  source, or task is installed by this crate."

Terrane fills every one of these slots with one program and its SDK.

## Role mapping

| RFC-0021 component | Terrane | Notes |
| --- | --- | --- |
| `aos-viewd` | `terrane serve` role (spec `03-architecture-overview.md`, ARCH-7 to ARCH-10) | Unprivileged, holds network credentials and host-tier tokens, runs the `tiered` store and repository, compiles indexes, supervises workers |
| `aos-view-publisher` | `terrane publish` role (spec `14-host-tier.md`, HOST-6 to HOST-9) | Networkless, sole owner of `sealed/`, fs-verity seal before no-replace publication |
| Per-view FUSE workers | `terrane fuse-worker` role (spec `27-surface-fuse.md`, FUSE-1 to FUSE-6) | One process per exposure, no network, backing handles from `serve`, passthrough registration through the broker |
| `aos-mountd` | Unchanged; the privileged mount broker Terrane never replaces (ARCH-9) | Performs `open_tree_attr`, `move_mount`, `MOVE_MOUNT_BENEATH`, and passthrough registration on behalf of workers |
| `aos-sandbox-storage` (ZFS datasets) | Unchanged in 1.0 for live workspaces; see [`06-decision-register.md`](06-decision-register.md) AD-4 | Private CoW views may be either a ZFS clone or a Terrane overlay upper; immutable views are Terrane |
| Attachment | Exposure (spec `26-surfaces.md`) | `view × surface × endpoint` with the sandbox as the endpoint owner |
| Portable tree | Terrane tree (spec `06-tree-format.md`) with the RFC-0021 profile as an adapter | See §descriptor bridging |
| Cache layers (`06-cache-memory-and-oom.md`) | Host tier (spec `14-host-tier.md`) | The four RFC-0021 layers map to tree bundles, index files, `chunks/`, and `sealed/` |

- **[SBX-1]** The `aos-viewd` service identity in RFC-0021 MUST be provided
  by `terrane serve` and no separate view daemon MUST be written. *Gate:*
  `checks.terrane.integration.viewd-role`.
- **[SBX-2]** The `aos-view-publisher` identity MUST be provided by
  `terrane publish`. The RFC-0021 publisher binary in
  `crates/aos-sandbox-broker-session-security/src/bin/aos-view-publisher.rs`
  MAY remain as a thin adapter that execs the Terrane role, and MUST NOT own a
  second sealed root. *Gate:* `checks.terrane.integration.publisher-role`.
- **[SBX-3]** Terrane roles MUST NOT gain mount-namespace authority.
  Every privileged mount operation MUST continue to go through `aos-mountd`
  as RFC-0021 `04-filesystem-views.md` §Native mount path specifies.
  *Gate:* `checks.terrane.integration.no-privileged-mounts`.

## Process and cgroup layout

RFC-0021 places view services in `aos-view-services.slice` and control
services in `aos-control.slice`. Terrane roles fit that layout without a new
slice:

```text
aos-control.slice
  terrane-serve.service          serve role, network, host tokens
aos-view-services.slice
  terrane-publish.service        publish role, no network, owns sealed/
  terrane-fuse-worker@<id>.service   one per exposure, no network
  terrane-gc.service             host-local collector (spec GC-25)
  terrane-job@<id>.service       tree jobs started from exposures (JOB-33)
```

- **[SBX-4]** FUSE workers MUST run outside every sandbox's cgroup and
  freezer domain, as RFC-0021 `02-architecture.md` §Per-view FUSE workers and
  spec FUSE-4 both require. *Gate:* `checks.terrane.integration.worker-cgroup`.
- **[SBX-5]** Worker upgrades MUST drain and remount (spec FUSE-48, FUSE-49);
  no `SCM_RIGHTS` connection handoff is permitted, matching RFC-0021's
  decision to reject fd handoff. *Gate:* covered by
  `checks.terrane.gates.fuse-worker-isolation`.

## Attachments as exposures

An RFC-0021 attachment request resolves to a semantic tuple: consumer
sandbox and incarnation, expected generations, source capability and view
revision or live generation, destination slot, closed mount attributes, lease
identity and expiry. A Terrane exposure carries the same information:

| RFC-0021 attachment field | Terrane exposure field |
| --- | --- |
| source capability + view revision | `view` selector: a fixed commit for immutable views, a ref for `follow` |
| live generation | `follow` reader mode (spec CONS-29) |
| destination slot | `at` endpoint, owned by the broker's attachment anchor |
| closed mount attributes | surface options (`ro`, `nosuid`, `nodev`, `noexec`, `allow_other`) |
| lease identity and expiry | exposure lease (spec FUSE-47) |
| mutation model (Immutable, Private CoW, Publishable staging) | writer mode `manual`/`periodic`/`sync` plus upper (spec CONS-7) |

- **[SBX-6]** RFC-0021 view modes MUST map as follows: Immutable to a
  `pinned` read-only exposure; Private CoW to a writable exposure in
  `manual` mode whose upper is discarded at teardown; Publishable staging to
  a writable exposure in `manual` mode whose commit lands on a branch the
  sandbox's token may write; Live read-only and Live read-write remain native
  mounts outside Terrane. *Gate:* `checks.terrane.integration.view-modes`.
- **[SBX-7]** The sandbox controller's durable attachment record MUST store
  the exposure id and the resolved commit, never a host path, PID, or mount
  option string, preserving RFC-0021's rule that public requests contain no
  host identifiers. *Gate:* `checks.terrane.integration.attachment-record`.
- **[SBX-8]** Replacement of a `follow` exposure's commit MUST use the same
  `MOVE_MOUNT_BENEATH` replacement the broker already implements, so that
  spec CONS-29's atomic whole-namespace switch is the broker's existing
  operation. *Gate:* `checks.terrane.integration.follow-replace`.

## Disclosure domains

RFC-0021 `06-cache-memory-and-oom.md` defines four domains: public verified
content, project, explicitly configured trust group, and private sandbox.
Spec `24-disclosure-domains.md` defines `public`, `tenant:<n>`, `group:<n>`,
and `private:<id>`.

- **[SBX-9]** The mapping MUST be: public to `public`; project to
  `tenant:<project-id>`; trust group to `group:<group-id>`; private sandbox
  to `private:<sandbox-id>`. The mapping is recorded once in the AOS glue
  crate and MUST NOT be duplicated in policy text. *Gate:*
  `checks.terrane.integration.domain-map`.
- **[SBX-10]** RFC-0021's strict-isolation guarantees (no cross-domain
  clones, reflinks, block dedup, or shared ARC identity) MUST be provided by
  spec DOM-12 to DOM-15 (per-domain object directories and sealed objects) and
  HOST-27, with `wipe` set per domain. Where RFC-0021 requires separate
  datasets or pools for a strict placement, the AOS module MUST place that
  domain's host tier on a separate filesystem. *Gate:*
  `checks.terrane.gates.dom-host-isolation`.

## Descriptor bridging

RFC-0021 `09-portable-format-profile.md` identifies portable objects by a
four-element descriptor with SHA-256 over the preimage
`"aos-sandbox-object-v1\0" || u16be(len(media-type)) || media-type ||
u64be(len) || bytes` (`crates/aos-sandbox-core/src/format/mod.rs`). Terrane
identifies content by BLAKE3 over `terrane-*-v1` domain prefixes (spec OBJ-1
to OBJ-4) and says a second digest algorithm is a new profile that coexists
(OBJ-8, OBJ-9).

Two facts make the bridge cheap: an RFC-0021 descriptor is a function of
bytes Terrane already holds, and Terrane carries SHA-256 as a per-object
derived attribute (spec DRV-6) that index trees can look up (DRV-12).

- **[SBX-11]** AOS MUST register a second Terrane descriptor profile,
  `aos-sandbox-v1`, whose algorithm is SHA-256 and whose single domain string
  is `aos-sandbox-object-v1`, following spec OBJ-9. The profile is
  registered in the AOS glue crate, not in the specification. *Gate:*
  `checks.terrane.integration.descriptor-profile`.
- **[SBX-12]** Every root that RFC-0021 consumers read MUST carry the
  requirement properties `hashes = [blake3, sha256]` and
  `index = [hash.sha256]` (spec PROP-18, PROP-20) so that an RFC-0021
  descriptor resolves to a Terrane object by one index-tree lookup. *Gate:*
  `checks.terrane.integration.sha256-index`.
- **[SBX-13]** The RFC-0021 media types (`application/vnd.aos.sandbox.*`) are
  carried as the manifest's advisory media type (spec OBJ-18) and as the
  entry attribute `aos.media_type`. The Terrane object identity never
  includes them. *Gate:* `checks.terrane.integration.descriptor-profile`.
- **[SBX-14]** The RFC-0021 portable tree encoding (deterministic CBOR under
  `portable-v1.cddl`) MUST be an import and export adapter over Terrane
  trees, registered as `aos-portable-tree` alongside the NAR, git, and OCI
  adapters (spec MIG-5). RFC-0021's canonical-encoding rules are the same
  rules the Terrane profile uses (spec TREE-25 to TREE-28), so the adapter is
  a re-keying, not a re-encoding of leaves. *Gate:*
  `checks.terrane.integration.portable-adapter`.

## Filling the dormant traits

- **[SBX-15]** `ObjectSource` MUST be implemented by a type in the AOS glue
  crate that opens a Terrane object through the SDK (`Store::get` with
  ranges, spec STORE-4) and streams it without retaining the whole object,
  satisfying the trait's bounded-buffering contract. *Gate:*
  `checks.terrane.integration.object-source`.
- **[SBX-16]** `ImmutableFetchTransport` MUST be implemented over the Terrane
  wire protocol client (spec `18-protocol.md`), mapping `FetchAttempt`,
  `FetchRecovery`, and ambiguity tokens onto `PresignRead` and `GetRange`
  with the protocol's retryable error classes (PROTO-47). *Gate:*
  `checks.terrane.integration.fetch-transport`.
- **[SBX-17]** Once SBX-15 and SBX-16 are green, the RFC-0021 phrase "No
  concrete network client ... is installed" in `remote_source.rs` MUST be
  updated to name the Terrane transport, and the `aos-sandbox-view` row of
  RFC-0021's crate plan MUST be marked superseded by `aos-terrane`.

## Cache layers and memory

RFC-0021 `06-cache-memory-and-oom.md` requires reserve-then-evict admission,
memory permits before allocation, pins and reservations kept separate from
residency, and that chunked content be "verified and assembled once into a
stable immutable backing file before passthrough". Spec HOST-10 to HOST-13
(reassembly), HOST-17 to HOST-24 (S3-FIFO, pins, reservations, exact quotas),
and FUSE-26 (seal before serve) are the same requirements stated once.

- **[SBX-18]** The AOS module MUST size the host tier from the same capacity
  inputs RFC-0021 uses for `ephemeral-storage`-style reservations and MUST
  expose spec OBS-11's residency and eviction metrics under the RFC-0021
  observability names. *Gate:* `checks.terrane.integration.capacity`.
- **[SBX-19]** RFC-0021's memory-permit rule MUST be met by spec FUSE-5
  (explicit worker limits) and PERF-7 (no per-entry heap for untouched
  entries). *Gate:* `checks.terrane.gates.perf-inode-memory`.

## Nix store views

RFC-0021 `07-project-environments-and-git.md` requires that a sandbox see the
exact authorized `/nix/store` closure as an append-only union of the closures
its executions have leased, never the host store, and never the daemon socket.

- **[SBX-20]** A sandbox's `/nix/store` MUST be an exposure of a view whose
  root is the union (spec ALG-25) of the leased closure roots, realized by
  the FUSE or EROFS surface with the Nix schema's canonical attributes (spec
  FUSE-22, EROFS-6). Adding a lease is a fast-forward commit that grafts
  another closure root (ALG-1). *Gate:* `checks.terrane.integration.nix-union`.
- **[SBX-21]** Nested sandboxes (RFC-0021's sibling model) MUST share the
  host's sealed object directory through a read-only `shared-dir` tier (spec
  STORE-14, VM-10) and MUST NOT run a second copy of the host tier. *Gate:*
  `checks.terrane.gates.perf-nested-zero-dup`.

## What RFC-0021 keeps

Terrane does not replace the sandbox controller, `aos-sandboxd`, the host,
network, and storage brokers, the broker session protocol, lease guards,
policy compilation, or the guest agent. It replaces the unwritten view
service, publisher, worker, compiler, and cache, and it changes the
descriptor profile from a single SHA-256 domain to a registered pair of
profiles.

## Interactions

- Spec files `03`, `14`, `24`, `26`, `27`, `28`, `20`.
- [`03-packaging.md`](03-packaging.md) for units and slices.
- [`05-implementation-plan.md`](05-implementation-plan.md) Phase 3.
- [`06-decision-register.md`](06-decision-register.md) AD-3, AD-4, AD-5.
