# 09 — Refs and commits

This file owns the only mutable state in a store: refs, the names that point
at commits, and the commit objects they point at. It defines the ref
namespace, the commit record, the conditional-write protocol that advances a
ref, epoch fencing, the reflog, tags, merge-base computation, rollback,
watching, and the notion of a ref's home. The bucket keys that hold refs are
in [`13-bucket-layout.md`](13-bucket-layout.md); the tree algebra that
produces the roots refs name is in [`07-tree-algebra.md`](07-tree-algebra.md).

## Model

Everything in a store is immutable and content-addressed except refs. A
[commit](02-glossary.md#the-five-nouns) binds a tree root to its parents and
provenance and is itself immutable; a [ref](02-glossary.md#the-five-nouns) is
a small logically mutable record naming a commit. Publication also selects
the catalog, retained history, collector lease and checked serving evidence.
Their coordination has one commit point: create-if-absent at the next
immutable publication slot. The selected transaction supplies whole-record
logical compare-and-swap without a separate database. The complete protocol
is [`reference/publication-authority.md`](reference/publication-authority.md).

The ref namespace and the commit graph follow git's shape, because git's
shape is right for this problem: branches advance, tags are permanent,
commits form a DAG with parents, and the reflog is a history of where a name
has pointed. The object encoding is not git's, for the reasons in
[`39-decision-register.md`](39-decision-register.md).

## Ref namespace

- **[REF-1]** A ref name MUST match `refs/<class>/<path>` where `<class>` is
  one of `heads`, `tags`, `notes`, `jobs`, `conflicts`, `derived`, and
  `<path>` is one or more
  non-empty segments of printable ASCII excluding `/`, the segment `.`,
  consecutive dots `..`, control
  characters, and the characters `~^:?*[\`. Names are case-sensitive.
  *Gate:* `gate:ref-names`.
- **[REF-2]** `refs/heads/<path>` is a **branch**: it advances by
  compare-and-swap. `refs/tags/<path>` is a **tag**: it is written by
  put-if-absent and MUST NOT be changed or deleted except by a principal
  holding `admin` on it and never by an ordinary commit. A snapshot is a tag.
- **[REF-3]** `refs/notes/<path>` holds advisory sidecar refs (access
  profiles, derivation memos, completeness caches) whose loss MUST NOT affect
  correctness. These sidecar values are opaque records, not `RefRecord`
  commit pointers; their bytes MUST NOT establish content reachability.
  `refs/jobs/<id>` holds tree-job checkpoints
  ([`32-tree-jobs.md`](32-tree-jobs.md)). `refs/conflicts/<ref>/<seq>`
  holds a commit whose merge into `<ref>` produced an unresolvable conflict
  value ([`20-consistency.md`](20-consistency.md)); it is a branch that
  advances only by resolution. `refs/derived/<path>` holds derivations
  ([`10-derived-data.md`](10-derived-data.md)) that are worth sharing by
  name, such as ruleset-derived realization roots
  ([`31-routing-rulesets.md`](31-routing-rulesets.md)); like `notes`, its
  loss MUST NOT affect correctness.
- **[REF-4]** The **reflog** of a branch contains one committed record per
  sequence number, selected from immutable proposals by the head's candidate
  ID and complete predecessor chain. New proposals use the create-once key
  `logs/<ref>/<seq>:<candidate-id>` in the key registry; sequence-only records
  remain readable through version-1 compatibility or their version-2
  `<seq>:legacy` keys after qualified migration (BKT-3). A proposal is not
  committed merely because its sequence is no greater than the current head's.
  The reflog is part of the namespace for reading but is not itself a ref.
  Removal MUST retain the exact last-selected whole head under D-79's
  complete retained-history selector; absence MUST NOT select a proposal
  or discard committed history.

## Ref record

A ref record is the canonical CBOR map defined in
`reference/terrane-v1.cddl` as `RefRecord`:

```text
commit        hash of the commit this ref names
seq           unsigned, strictly increasing per ref, 1 for the first write
writer_epoch  unsigned, fencing token for the current writer
home          locality label of the authority that owns this ref
policy        optional map: multi-writer policy, retention, conflicted flag
candidate-id  optional 32-byte selector, required for new branch advances
```

- **[REF-5]** `seq` MUST increase by exactly 1 on every successful advance of
  a branch. A reader that observes `seq` decrease or skip MUST treat the ref
  as corrupt and refuse to act on it.
- **[REF-6]** `writer_epoch` MUST be greater than or equal to the previous
  record's `writer_epoch`. A write with a lower epoch MUST be rejected by the
  authority regardless of the outcome of the compare-and-swap. *Gate:*
  `gate:ref-epoch-fencing`.
- **[REF-7]** `home` MUST be set on the first write and MUST NOT change
  except through the region-move procedure in
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md).

## Commit object

A commit is the canonical CBOR map `Commit` in `reference/terrane-v1.cddl`,
identified by its hash in the `commit` identity domain
([`04-content-model.md`](04-content-model.md)):

```text
tree        root hash
parents     ordered list of commit hashes; empty for a root commit
provenance  principal, token id, issuer, process identity (23)
timestamp   unsigned seconds since epoch as asserted by the committer
message     UTF-8 text, MAY be empty
profile-pair  map: chunk profile, tree-format version,
            recipe, conflicted flag, lease, required-property snapshot,
            signed entry-origin receipts
packs       optional list of (pack id, locality) for packs first written by
            this commit
signature   detached signature over the preceding fields (23)
```

- **[REF-8]** A commit MUST name exactly one tree root. A commit produced by
  a merge MUST list `ours` first and `theirs` second in `parents`. A fold
  MUST record both ([`07-tree-algebra.md`](07-tree-algebra.md)).
- **[REF-9]** `profile-pair` MUST record the chunk profile
  ([`05-chunking.md`](05-chunking.md)) and the tree-format version in
  effect at the commit. The identity profile is fixed by the store's
  `store-profile` ([`04-content-model.md`](04-content-model.md) OBJ-8), not
  repeated in this map. The commit MUST set `conflicted=true` when the tree
  contains a conflict value. It MUST record the recipe when the tree was
  produced by materializing a composite (a derivation,
  [`10-derived-data.md`](10-derived-data.md)).
- **[REF-10]** `packs` SHOULD list every pack that this commit was the first
  to reference, with the locality where it was written. Readers in another
  locality use this list to fetch across regions before replication has
  completed ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)),
  in the manner of a git promisor remote.
- **[REF-11]** `timestamp` is advisory. Ordering of commits MUST be derived
  from `parents` and `seq`, never from `timestamp`, except where a merge
  policy explicitly selects `prefer-newer`.

## Advancing a branch

The write protocol has three phases and depends on their order for safety
under concurrent garbage collection ([`17-garbage-collection.md`](17-garbage-collection.md)).

- **[REF-12]** A writer MUST complete these steps in order: (1) write every
  pack the commit needs and its per-pack index; (2) write the commit object;
  (3) write a reflog candidate at `logs/<ref>/<seq+1>:<candidate-id>` by
  put-if-absent, including the whole new record and complete expected previous
  record; (4) compare-and-swap `<ref>` from the record it
  read to the new record. A failure before step (4), or a compare-and-swap
  conflict at step (4), MUST leave the ref unchanged by this writer. An
  unavailable storage or transport result at step (4) can be indeterminate:
  the atomic write may already have applied even though its acknowledgement
  or durability confirmation failed. Such a result MUST NOT be reported as
  success or as a confirmed rejection. The writer MUST stop its session and
  re-read the authoritative ref after the backend becomes available before
  any further advance; it MUST NOT blindly retry the same transaction. A
  failed re-read remains indeterminate and MUST NOT be interpreted as ref
  absence. Every restarted transaction MUST allocate a fresh secure-random
  32-byte candidate ID; a bounded in-flight attempt may retain its ID. Before
  applying the CAS, the authority MUST verify that the selected candidate
  exists and its whole new and previous records equal `new` and `expect`.
  Final checked publication MUST use the selected transaction protocol in
  [`reference/publication-authority.md`](reference/publication-authority.md),
  retaining actual backend exclusion and current source, catalog, trust and
  retention checks through its commit point. Raw CAS MUST invalidate the
  target's checked lineage rather than manufacture verified serving evidence.
  *Gate:* `gate:ref-advance-ordering`.
- **[REF-13]** Step (3) MUST use put-if-absent on the exact candidate key.
  An existing candidate means collision or duplicate append, not proof that
  the head advanced. The writer MUST re-read the ref; an unchanged head
  permits a fresh candidate within the original commit deadline. A changed
  head or CAS mismatch requires either failure (single-writer mode) or rebase
  by merge (multi-writer mode) and retry from step (2). An abandoned proposal
  MUST NOT reserve the successor sequence against later writers.
- **[REF-14]** The compare-and-swap in step (4) MUST compare the whole
  previous record (or its backend version token), not only `seq`.
- **[REF-15]** A writer MUST abort a commit whose elapsed time since step (1)
  began exceeds the store's grace window
  ([`17-garbage-collection.md`](17-garbage-collection.md)) minus a safety
  margin, and MUST NOT retry it without rewriting its packs.

### Single writer and multi writer

- **[REF-16]** A branch is single-writer by default. A writer obtains the
  branch's current `writer_epoch`, increments it on its first write, and
  uses the incremented value for the lifetime of its session. Any later
  write with a lower epoch is fenced by REF-6.
- **[REF-17]** A branch MAY be marked `multi_writer=true` in its ref policy
  with a merge policy list ([`07-tree-algebra.md`](07-tree-algebra.md)). In
  this mode a losing writer MUST rebase by
  `merge(base=read commit, ours=current head, theirs=own commit)` and retry.
  A conflict that the policy list resolves to `error` MUST fail the write.
- **[REF-18]** In single-writer mode a losing writer MUST fail with a
  fencing error and MUST NOT retry with the same epoch.

## Tags

- **[REF-19]** A tag MUST be written with put-if-absent. A second write to
  an existing tag name MUST fail. A tag record MUST have `seq=1` and its
  `writer_epoch` MUST record the authorized source ref's observed current
  epoch. It is an authority snapshot/fence, not a principal-wide epoch.
  Creation MUST use a guard-issued publication context bound to the complete
  source record and the tagging principal's current `tag` authorization.
  Source authorization and the whole source record MUST be revalidated before
  create-once publication; a changed source requires a fresh context.
  `commit` authority or a commit writer session MUST NOT be required merely
  to create a tag.
- **[REF-20]** An **annotated tag** MAY carry, in its record's `policy`, a
  snapshot envelope: a signed statement binding the tag name, the commit, and
  arbitrary attestation data. The envelope format is `SnapshotEnvelope` in
  `reference/terrane-v1.cddl`. For a new envelope its signer identifier is
  the lowercase 64-character terminal Ed25519 public key, authenticated by
  the tagging principal's capability chain. Its preimage is the canonical
  envelope map with key 5 absent, without an additional prefix. Verification
  MUST bind the expected tag name and commit as well as that terminal key.
  First creation MUST use the source `tag` grant (or `admin` through its
  implication), without an additional `admin` requirement for an annotation.
  Applicable target namespace, root and token caveats MUST still be enforced.
  Changing an existing immutable tag remains subject to REF-2.

## Reflog

- **[REF-21]** Every advance of a branch MUST leave a reflog record. The
  record MUST contain the new ref record, the previous commit hash, the
  principal, and a reason string (`commit`, `merge`, `fold`, `rollback`,
  `job-checkpoint`, `migrate`). A new candidate record MUST also contain
  the complete expected previous RefRecord, or null when currently absent.
  Recreation with retained history MUST include key 7's exact last-selected
  predecessor, continue its sequence, and preserve epoch/home fencing.
  The previous-commit field MUST agree with that retained predecessor when
  present, otherwise with the expected record or fresh-name null.
  The new RefRecord MUST carry the candidate ID that selects this proposal.
- **[REF-22]** Reflog records are garbage-collection roots under the
  effective `retain` mode. For `retain=gc`, the effective `reflog_retain`
  property selects a duration or the newest committed record count; `lease`,
  `ttl` and `forever` use their respective rules
  ([`17-garbage-collection.md`](17-garbage-collection.md)). Expiry removes
  the record from
  retained content roots; its commit becomes unreachable unless another root
  reaches it. Candidate metadata still required to traverse a selected
  chain or an active collection snapshot MUST remain readable. Preserving
  this chain metadata does not keep expired content live.
- **[REF-23]** Reading `logs/<ref>/` for a registered branch MUST return
  records in
  sequence order. Readers MUST follow the authoritative head's candidate
  and whole predecessor records, then return that selected chain in ascending
  order. An absent branch MUST begin at its exact retained selected head,
  following recreation key 7 where present. Unknown legacy selection MUST
  refuse exhaustive history claims. Legacy numbered records are bounded by
  the selected legacy record; pending proposals beyond it are not visible.
  A request beyond the last
  selected sequence returns no records. Gaps MUST be reported; a reader MUST
  NOT infer a gap means an advance did not occur or enumerate proposals
  using LIST.

## Merge base and ancestry

- **[REF-24]** The **merge base** of two commits MUST be computed as the
  lowest common ancestor in the commit DAG by parents, with ties broken by
  preferring the ancestor with the greater `seq` on the branch being merged
  into. When there are multiple lowest common ancestors an implementation
  MUST recursively merge them (the "recursive" strategy) or fail with a
  distinct error; it MUST NOT pick one arbitrarily.
- **[REF-25]** An implementation MUST provide `is_ancestor(a, b)`. A fold
  MUST verify that the child's fork point is an ancestor of the parent's
  current commit before merging and MUST fail otherwise.
- **[REF-26]** A commit MUST NOT be reachable from itself. A writer MUST
  reject a commit whose parents include a descendant of the commit being
  written.

## Rollback

- **[REF-27]** Rollback of a branch to an earlier commit MUST be an ordinary
  advance: a new reflog record with reason `rollback` and a compare-and-swap
  to a record naming the earlier commit with `seq+1`. The rolled-past
  commits remain in the reflog and remain roots until reflog expiry.

## Watching

- **[REF-28]** An authority MUST offer a watch on a ref that delivers each
  new record in sequence order without gaps for the duration of the watch.
  A watcher that reconnects MUST receive the current record first and MAY
  request the reflog from a given `seq` to fill what it missed. Branch
  watches MUST deliver only candidate-selected committed records; an
  abandoned proposal MUST NOT be delivered as an advance.
- **[REF-29]** A cache tier serving a ref it does not own MUST report the
  age of its copy and MUST offer a fresh read that consults the authority
  ([`20-consistency.md`](20-consistency.md)).

## Home

- **[REF-30]** Every ref has a **home**: the authority store, in a locality,
  that performs its compare-and-swap. Writers MUST send advances to the home.
  Readers MAY read mirrored copies subject to REF-29.
- **[REF-31]** A branch fork MAY choose a home different from its parent's,
  and SHOULD choose the locality of its expected writer, so that a job's
  commits never cross regions. A fold sends the merged commit to the
  parent's home.

## Interactions

- [`04-content-model.md`](04-content-model.md) defines the commit identity
  domain and hash.
- [`07-tree-algebra.md`](07-tree-algebra.md) defines fork, fold, merge,
  fast-forward, and conflict values.
- [`13-bucket-layout.md`](13-bucket-layout.md) maps ref names and reflog
  records to bucket keys and states which conditional-write headers each
  backend must support.
- [`17-garbage-collection.md`](17-garbage-collection.md) uses refs and
  reflog records as roots and relies on REF-12's ordering.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) and
  [`20-consistency.md`](20-consistency.md) define home-region behavior,
  mirrored reads, and staleness reporting.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)
  gates every advance by the `commit`, `fork`, and `tag` verbs.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md) defines the
  provenance and signature fields of a commit.

## Informative: why one conditional write is enough

Each writer seals its own packs and publishes immutable index generations.
One create-once slot selects a complete transaction over the logically
mutable records. This keeps publication database-free while preventing
independent head, catalog or lease updates from leaving stale checked
serving evidence current. A reflog proposal alone never wins that slot.
