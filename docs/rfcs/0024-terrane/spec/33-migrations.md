# 33 — Migrations

This file owns every kind of change that moves data or identity from one
shape to another: importing content from a foreign cache, changing a
namespace's layout, changing an encoding or chunking profile, moving between
buckets, regions, or providers, and splitting or joining tenants. Each is
expressed as "produce a new root, merge it against whatever landed meanwhile,
update one ref", executed by a [tree job](32-tree-jobs.md). Every migration
has a rollback, and the one thing no migration can do is change the digest
domain of existing identities.

## Model

Because the only mutable state is a ref and every merge costs time
proportional to the difference between its inputs, a migration is never a
copy. It is a transform from an old root to a new root, followed by a
three-way merge against concurrent commits, followed by one conditional
write. Rollback is the reverse conditional write. Data is never rewritten
unless the migration changes chunk boundaries, and even then old and new
content coexist under one tree until garbage collection removes what nothing
references.

| Migration | New root produced by | Data rewritten | Cutover |
| --- | --- | --- | --- |
| import | adapter `transform` job | imported bytes chunked once | fold into target |
| layout | `map` over paths | none | ref CAS |
| profile (encoding) | re-encode nodes | none | ref CAS + profile bump |
| chunk parameters | lazy re-chunk job | yes, per file, lazily | per-file merge |
| bucket / region / provider | idempotent object copy | none (copied) | ref CAS in new store |
| tenant split / join | `split` / `graft` / set ops | none | ref CAS per root |

## Import adapters

An import adapter reads a foreign cache and produces a tree whose entries
follow the [schema](26-surfaces.md) of the surface that will later serve it.
Imports run as `transform` jobs on an import branch and fold into the target.

- **[MIG-1]** An import MUST run on a branch `refs/jobs/import-<id>` forked
  from the target, and MUST fold by merge; it MUST NOT write directly to the
  target ref. *Gate:* `gate:mig-import-branch`. *See:*
  [`32-tree-jobs.md`](32-tree-jobs.md).
- **[MIG-2]** Imported content MUST be chunked with the target root's
  effective `chunk` property and verified against the foreign cache's own
  digests before any entry is committed. An adapter MUST record the foreign
  digest as an entry attribute (for example `hash.sha256`,
  `nar.hash_sha256`, `oci.digest`) so the foreign name remains resolvable through an
  [index tree](10-derived-data.md). *Gate:* `gate:mig-import-verify`.
- **[MIG-3]** Import MUST be idempotent per foreign object: rerunning an
  import over a partially imported cache MUST skip objects whose foreign
  digest is already present in the target's index tree and MUST produce the
  same tree as a single complete run. *Gate:* `gate:mig-import-idempotent`.
- **[MIG-4]** Import MUST deduplicate at the file level by content hash before
  chunking: an adapter that can compute the file content hash cheaply (from
  the foreign cache's metadata) MUST consult the side table and skip upload
  when the object is already present.
- **[MIG-5]** The following adapters are registered and MUST map to the named
  surface schema in [`reference/surface-registry.md`](reference/surface-registry.md):

  | Adapter | Source | Schema | Entry attributes retained |
  | --- | --- | --- | --- |
  | `nix-cache` | narinfo + NAR over HTTP or file | `nix-cache` | `nar.hash_sha256`, `nar.size`, `nar.references`, `nar.deriver`, `nar.signatures`, `nar.ca` |
  | `reapi-cas` | REAPI CAS and Action Cache | `reapi` | `hash.sha256`, `reapi.size_bytes`, `reapi.output_digests` |
  | `gha-cache` | GitHub Actions cache API | `gha-cache` | `gha.key`, `gha.version`, `gha.scope`, `gha.created_at` |
  | `oci` | OCI Distribution registry | `oci` | `hash.sha256`, `oci.media_type`, `oci.annotations`, `oci.subject`, tag history |
  | `git` | git repository or packfiles | `git` | `hash.git-blob-sha1`, mode bits |
  | `terrane-compatible` | a chunk store with identical CDC parameters and hash | any | all |

- **[MIG-6]** The `terrane-compatible` adapter MUST re-index rather than
  re-chunk when the source uses the same chunking parameters
  ([`05-chunking.md`](05-chunking.md)) and the same chunk hash function:
  chunk identities are equal by construction, so the adapter copies or
  references packs and writes index entries without decompressing content.
  The adapter MUST verify a sample of chunks (at least one per source pack)
  before trusting the source's boundaries. *Gate:* `gate:mig-reindex`.
- **[MIG-7]** An adapter MUST NOT trust a foreign cache's claim of a Terrane
  identity. Object and tree hashes are always recomputed; only foreign
  digests are copied as attributes.

## Namespace and layout changes

Renaming a key scheme, moving a prefix, reorganizing roots, or stripping
attributes is a `map` or `graft`/`split` over the tree.

- **[MIG-8]** A layout migration MUST be expressed as a
  [tree algebra](07-tree-algebra.md) expression recorded as the new root's
  recipe, applied by a `transform` job, and cut over by one conditional write
  of the target ref. *Gate:* `gate:mig-layout`.
- **[MIG-9]** A layout migration MUST NOT change any object identity. Entries
  keep their object hashes; only keys, `tree` entry placement, and attributes
  change.
- **[MIG-10]** Concurrent commits landing during a layout migration MUST be
  reconciled by three-way merge with the pre-migration commit as base. Where
  the migration moved a subtree and a concurrent commit changed entries
  inside it, the merge MUST apply the concurrent change at the moved location
  (rename-aware merge on `tree` entries). *Gate:* `gate:mig-layout-merge`.
- **[MIG-11]** Consumers that hold a fixed commit (pinned views) are
  unaffected by a layout migration. Consumers that follow a branch observe
  the new layout atomically at the cutover commit
  ([`20-consistency.md`](20-consistency.md)).
- **[MIG-12]** A layout migration SHOULD leave a `tree` entry or symlink at
  the old location pointing at the new one for one retention period when
  surfaces with fixed schemas depend on the old layout; the surface registry
  names which surfaces require this.

## Encoding profile changes

Node encoding, entry attribute schema, and commit format are versioned by
media type ([`04-content-model.md`](04-content-model.md)). A new version is
a new profile.

- **[MIG-13]** The profile of a root MUST be recorded in the ref's commit
  ([`09-refs-and-commits.md`](09-refs-and-commits.md)) and MUST be one of
  the registered profiles. Readers MUST accept every profile they claim
  conformance to for the duration of the migration window declared in the
  profile registry. *Gate:* `gate:mig-profile-read`.
- **[MIG-14]** A profile migration MUST re-encode nodes on a job branch and
  cut over by ref CAS with the profile field bumped in the same commit. It
  MUST NOT change entry keys, object hashes, or attributes; a profile
  migration whose output tree differs from its input in anything but node
  bytes is a conformance error. *Gate:* `gate:mig-profile-identity`.
- **[MIG-15]** Because tree node identity is the hash of node bytes, a
  profile migration changes root hashes. The cutover commit MUST record the
  pre-migration root as a parent so that history, merge bases, and
  provenance are preserved across the encoding change.
- **[MIG-16]** Mixed-profile trees (a `tree` entry under one profile pointing
  at a root under another) MUST be readable during the migration window and
  MUST be reported as incomplete by [completeness](08-properties.md) on the
  `profile` property.

## Chunk-parameter changes

Changing the content-defined chunking parameters or the chunk compression
codec produces new chunk identities for the same bytes. Object identity
does not change if the object's content hash is unchanged
([`04-content-model.md`](04-content-model.md)).

- **[MIG-17]** The effective `chunk` property of a root MUST be part of the
  root's profile. Changing it MUST NOT invalidate existing entries: readers
  MUST resolve an entry's chunks by the chunk list in its manifest regardless
  of the currently effective parameters. *Gate:* `gate:mig-chunk-read`.
- **[MIG-18]** A chunk-parameter migration MUST be a lazy `transform` job
  that, per file, re-chunks content, uploads new chunks, writes a new
  manifest, and replaces the entry's manifest reference, committing in
  batches and folding by merge. The file content hash MUST be recomputed and
  MUST equal the old value, otherwise the entry is marked failed and not
  replaced. *Gate:* `gate:mig-rechunk`.
- **[MIG-19]** New commits under the root MUST use the new parameters from
  the moment the property changes; the migration job covers only entries
  that predate it, selected by filter `chunk_profile != current`.
- **[MIG-20]** Old chunks become unreferenced only when no manifest under any
  root references them, and are then collected by
  [garbage collection](17-garbage-collection.md) after the grace window.
  A chunk-parameter migration MUST NOT delete chunks itself.
- **[MIG-21]** Because compressed representation is not part of chunk
  identity ([`05-chunking.md`](05-chunking.md)), a codec or dictionary change
  MUST be applied by recompressing packs during
  [compaction](17-garbage-collection.md), never by a tree migration.

## Bucket, region, and provider moves

Every object except refs is immutable and idempotently writable, so a store
move is a copy followed by a ref cutover.

- **[MIG-22]** A store move MUST proceed in this order: (1) copy packs and
  indexes to the destination with idempotent puts or bucket-native
  replication; (2) run the destination in a `tiered` list ahead of the source
  for readers (`tiered[new, old]`), so misses fall through; (3) verify the
  destination holds every pack referenced by every ref's reachable set; (4)
  cut over each ref by conditional write in the destination with the source
  ref's commit and epoch; (5) mark the source read-only; (6) drain the source
  after the retention period. *Gate:* `gate:mig-store-move`.
- **[MIG-23]** During step (2), writers MUST commit to the destination
  authority once its ref exists and to the source until then; the switch is
  per ref and atomic with step (4). A writer MUST NOT observe a window where
  neither store accepts its commit.
- **[MIG-24]** A move between regions MUST update the `home` property of each
  moved root ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)) in
  the cutover commit. Non-home readers continue reading mirrored refs with
  their staleness bound throughout.
- **[MIG-25]** A move to a provider whose conditional-write capability is
  absent or unverified MUST fail the pre-flight probe of
  [`13-bucket-layout.md`](13-bucket-layout.md) before any ref is created
  there. *Gate:* `gate:bucket-probe`.
- **[MIG-26]** Multipart uploads abandoned by a failed copy MUST be aborted
  by the migration job so they do not accrue storage in the destination.

## Tenant and root splits and joins

- **[MIG-27]** Splitting a tenant or store MUST be `split(root, prefix)` into
  a new root under a new ref, with properties (domain, ACL, storage class)
  set explicitly on the new root before its ref is published. The new root
  MUST NOT inherit properties across the split; inheritance stops at a ref.
  *Gate:* `gate:mig-split-join`.
- **[MIG-28]** Joining MUST be `graft(parent, at, root)` and MUST fail closed
  when the grafted root's [disclosure domain](24-disclosure-domains.md) is
  more restrictive than the parent's effective domain at `at`.
- **[MIG-29]** Set operations (union with precedence, difference,
  intersection) used to separate or combine tenants MUST be recorded as
  recipes on the resulting roots so the operation is auditable and
  repeatable.

## The digest-domain limit

- **[MIG-30]** A change to the content hash function, the identity preimage
  prefix, or the chunk hash function MUST be introduced as a new identity
  profile that coexists with the old one. Existing identities MUST NOT be
  rewritten. Entries carry the algorithm tag of their identity, readers
  accept every registered algorithm they claim, and cross-profile references
  are ordinary `tree` entries. *Gate:* `gate:mig-digest-coexist`. *See:*
  [`04-content-model.md`](04-content-model.md).
- **[MIG-31]** A root whose entries span identity profiles MUST report
  completeness on the `identity_profile` property, and a backfill job MAY
  add the new profile's hash as a derived attribute without changing the
  entry's identity.

## Rollback

- **[MIG-32]** Every migration MUST be reversible until its source is
  drained, and the reversal MUST be documented for the kind:

  | Migration | Rollback |
  | --- | --- |
  | import | delete or discard the import branch; folded imports are reverted by a commit that removes the imported subtree, recorded in the reflog |
  | layout | conditional write of the ref back to the pre-migration commit; concurrent commits since cutover are re-merged onto the old layout by the inverse recipe |
  | profile | conditional write back; old nodes remain until garbage collection |
  | chunk parameters | none needed: old and new manifests are both valid; halt the job and optionally revert the property |
  | store move | conditional write of refs back in the source; the source was read-only, not deleted, until drain |
  | split / join | reverse operation with the recorded recipe |

- **[MIG-33]** Garbage collection MUST NOT sweep content reachable from any
  reflog entry younger than the migration retention period, so that every
  rollback in [MIG-32] has its content available. *Gate:*
  `gate:gc-reflog-roots`.

## Interactions

- [`04-content-model.md`](04-content-model.md) defines identity profiles and
  the algorithm tag.
- [`05-chunking.md`](05-chunking.md) defines the chunk profile and the rule
  that compression is not identity.
- [`07-tree-algebra.md`](07-tree-algebra.md) supplies the transforms.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) supplies profiles on
  commits and conditional writes.
- [`13-bucket-layout.md`](13-bucket-layout.md) supplies the conditional-write
  probe.
- [`17-garbage-collection.md`](17-garbage-collection.md) reclaims what
  migrations leave behind and honors reflog roots.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) defines `home`.
- [`24-disclosure-domains.md`](24-disclosure-domains.md) constrains joins.
- [`32-tree-jobs.md`](32-tree-jobs.md) executes every migration.
