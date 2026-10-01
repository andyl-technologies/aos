# Release stages and publication boundaries

A release stage is an unpublished candidate for a signed registry release. It
lets a maintainer upload part of a catalog, inspect the recorded object
inventory, resume interrupted work, and finalize the exact reviewed revision.
It uses the registry's existing Git, cache, signing, and publication machinery.
AOS-specific builds and qualification compose this machinery through
`aos maintain release`; ordinary registry maintainers use `apr release`.

## Three independent identities

| Identity | Meaning | What may change |
| --- | --- | --- |
| Authoring workspace | A maintainer's branch or local checkout | Package metadata and authoring commits |
| Stage id and revision | One candidate and an exact revision of its inventory | A new revision may replace candidate intent |
| Signed release version | An immutable semver tag and the artifacts it names | Channel selection may change; released bytes remain fixed |

Maintainer branches are workspaces. Configured channel names reserve
`refs/heads/<channel>` for the published rollout frontier, and semver names
reserve `refs/tags/<version>` for signed releases. Do not use a channel branch
as the live authoring pointer exposed to consumers. Public `HEAD` remains a
symref to `refs/heads/<default-channel>`. APM follows a signed channel
partition to the signed semver release and verifies that chain; a workspace
branch never grants release authority.

For a new origin, upload the signed registry initialization and its default
`HEAD` before staging the first version. Stage publication adds the immutable
release; initialize or advance a channel separately afterward. `--stage` and
`--from-stage` reject channel convenience flags. Direct releases retain their
existing optional channel workflow.

A stage is also independent of an environment. A registry may have unpublished
stages on its production surface or its staging surface. RFC-0017's
`staging/candidate` names a deployment and channel destination; it does not
mean an unfinished release stage. Upload completion, release finalization,
and channel promotion are distinct transitions.

## Inventory and concurrency

The stable stage id survives retries. Its revision binds the authoring commit,
intended version, immutable object inventory, and recorded upload progress.
Every inventory entry identifies exact bytes by digest and length. Artifacts
remain immutable even while the authoring workspace changes.

A mutation names the revision it observed. Compare-and-swap rejects a stale
revision rather than merging a partial inventory with a newer candidate.
Resume inspects the recorded inventory and continues the same revision; it
does not silently adopt the current workspace head. To change the candidate,
create a new revision and review its inventory before finalization.

Candidate preparation records the signed commit, release metadata, and exact
public pointer bytes in an isolated workspace. Finalization checks inventory
completeness and object identities, then publishes that frozen signed identity
and its withheld discoverable metadata after the objects exist. An already
released semver identity cannot be replaced by another commit, tag signature, cache inventory, or manifest. Retrying the exact
operation may reuse verified artifacts. Promoting that release selects its
existing immutable bytes rather than rebuilding or retagging them.

## Portable schema and local persistence

The portable revision schema is `aos.registry-stage/v1`. Its strict record
binds the registry, stage id, monotonic revision, semver `release_id`, ordinary
`source_branch`, exact prepared `commit`, canonical `inventory_digest`, and
retained `store_roots`. `inventory` is sorted by unique origin-relative path;
each entry carries `path`, `sha256`, `byte_size`, `kind`, and `media_type`.
`publication` retains exact prepared pointer bytes separately from immutable
objects so draft upload cannot accidentally publish refs or channel pointers.
An optional `container` graph binds the OCI repository, signed container release,
and complete descriptor inventory. Capturing the graph includes every manifest,
index, configuration, layer, and declared provenance/referrer artifact; it does
not treat a sidecar or an index digest alone as a complete upload. File and
static transports retain verified graph bytes under `oci/blobs/sha256/<digest>`;
the signed Git sidecar and immutable version tag retain release authority.
This archive does not provision a Docker Distribution endpoint. The Hub
adapter separately uploads real Distribution repository memberships and binds
its immutable OCI version tag. Distribution upload checkpoints retain
server-confirmed offsets for interrupted large blobs.
The Hub's advertised OCI endpoint is discovered from its surface capabilities;
it need not have the same base path as registry object storage.

OCI readiness requires the complete verified graph on every required physical
write placement. A standard Distribution upload materializes the primary
placement; existing authorized placement replication must fill any remaining
stores before the stage becomes ready. Staging does not provision replication.
Routing aliases for the same physical store add no requirement, and a single
write placement needs no replication.

The local producer adapter stores these records below its Git directory:

```text
.git/apr/stages/
  records/<id>.json             current revision and lifecycle state
  revisions/<id>/<n>.json       immutable revision record
  objects/<sha256>              exact immutable candidate bytes
  retention/<id>/<n>.json       retirement time for superseded or discarded roots
  caches/<id>/<n>/              generated candidate binary cache
  surfaces/<id>/<n>/            generated private publication files
  workspaces/<id>/<n>/          isolated candidate preparation
```

Revision numbers begin at `1`. Updating `--stage <id>` names the observed
`--stage-revision N` and creates revision `N + 1`. `--resume` with that id and
exact revision reuses the prepared signed bytes, rather than signing the
current authoring head again. Finalization names `--from-stage <id>
--stage-revision N`; it cannot select a different candidate by discovery.

| State | Meaning | Permitted progression |
| --- | --- | --- |
| `draft` | Candidate bytes are being authored or transferred | Resume, new revision, or discard |
| `ready` | The exact immutable inventory is available | Finalize, new revision, or discard |
| `releasing` | The selected revision is frozen while pointers are installed | Resume the same publication |
| `released` | The immutable release is published | Channel promotion preserves this identity |
| `discarded` | Candidate retention roots are relinquished | Collection follows retention policy |

Only `draft` and `ready` may acquire a new revision. `releasing` and `released`
freeze the selected signed identity. A failed or interrupted operation reports
its recorded state; inspect it before deciding whether to resume upload or
publication.

## Discovery and direct access

Unpublished stages are absent from default public catalogs, package and image
discovery, and channel partitions. Public pointers continue to identify the
last published release while a candidate is incomplete.

This is a publication boundary, not a confidentiality boundary. An explicitly
addressed authoring ref, object digest, cache URL, or CDN path may expose already
uploaded candidate bytes. Sensitive artifacts require access control on their
storage and transport. Hiding a stage from the catalog cannot revoke a URL
that a reader already knows.

A permissioned Hub stage UI and API track the same stage id, revision, and
inventory as the registry producer. Hub storage and presentation do not add a
second release authority. The Connect envelope is limited to 8 MiB. Candidate
metadata supports canonical plain JSON or gzip bytes, with a 32 MiB decoded
limit and at most 50,000 objects; gzip is limited to 6 MiB minus 4 KiB so its
base64 representation fits the RPC envelope. Pointer bytes use base64 strings.
Artifact bytes use object uploads and are outside these metadata limits.
Candidate metadata is stored in bounded 256 KiB database chunks to respect
provider row limits.
The Hub registry's canonical owner/name and APR's configured local alias may
differ; select the local alias whose upload destination is that Hub registry.
A local filesystem Git registry follows the same release and trust contracts
without a Hub account or service.

## Shared services and transport adapters

The pure registry schema owns stage identity, revisions, inventories, and
state transitions. Producer libraries own authoring, cache construction,
signatures, and release artifacts. Transport adapters provide narrow
operations for object inventory, object upload and read-back, stage persistence,
and publication. Static filesystem/HTTP/S3/SFTP adapters and the Hub adapter
compose the existing shared service machinery around those operations.

Candidate metadata is prepared before the transaction's review digests freeze.
APR and the AOS caller share the four-role registry catalog TUF producer and APM
verifier. External catalog signatures use the active registry authority and
committed catalog root, with role/version-bound `CatalogTuf` requests in the
`aos-registry-tuf-v1` SSHSIG namespace. Distribution-bundle TUF keys and digest
domains remain independent. A changed catalog carrying the base commit's stale
metadata fails verification before a release tag is created. Root rotation
checks use the highest published root metadata version; each role takes its
maximum version across all published tags as its floor. This history comes
from the local authoring registry and does not independently authenticate its
refs. Existing root cross-signature checks and final release verification
preserve the trust boundary, including a hotfix from an older release line.

AOS distribution metadata uses a separate, role-separated TUF contract. Hub
stage admission binds its prepared timestamp to the exact immutable snapshot,
root, targets, and delegated metadata bytes, then applies the existing
publication admission and monotonic timestamp rules. The signed registry tag
check authenticates the registry release. Consumers verify distribution TUF
signatures against independently pinned roots; admitting staged metadata does
not establish a new root authority.

The common release library drives both APR's ordinary registry workflow and
AOS's maintainer orchestrator. `aos maintain release` adds frozen source plans,
platform matrices, qualification, destination policy, receipts, and rollout
journals. It does not run APR subprocesses or duplicate the registry release
protocol. `aos release` has been removed; there is no compatibility alias.

## Retention

An active stage is a garbage-collection root for its recorded objects. Partial
uploads remain resumable while that root is active. Discarding or superseding
a stage begins a minimum 24-hour grace period in both local and Hub adapters;
it does not immediately delete uploaded bytes.

Collection works from the union of active stages, retained stage revisions,
released snapshots, channel partitions, shared objects, and legal/source
retention roots. Expiration of one stage cannot delete a digest referenced by
another stage or a release. A released identity and required corresponding
source retain their release policy independently of stage cleanup.

Local `apr cache gc` and automatic cache cleanup honor stage retention under
the producer lock. They collect eligible aged canonical stage CAS objects and
cache pairs. After a known revision's grace period expires, its generated
`caches/<id>/<n>/` and `surfaces/<id>/<n>/` directories are also eligible for
collection. Active revisions and shared object references remain protected;
removing a discarded hardlink preserves the bytes referenced by an active
candidate. Unexpected files or links preserve a generated directory for review.

Revision history, metadata, and actual preparation workspaces under
`workspaces/<id>/<n>/` remain retained. Dry-run reports the same candidates
without creating or deleting files.

## Related documentation

- [Publishing](publishing.md) describes the producer's command surface and
  immutable-first public upload order.
- [Publish packages and releases](../users/registry/publishing.md) gives the
  operator workflow.
- [Versioning and channels](versioning-and-channels.md) specifies the existing
  frontier refs and signed partition schema.
- [RFC-0017](../rfcs/0017-canonical-hub-publishing/README.md) specifies AOS
  destination, qualification, and production publication policy.
