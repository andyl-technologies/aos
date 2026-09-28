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
a small mutable record naming a commit. Because refs are the only thing that
changes, they are the only thing that needs coordination, and the
coordination required is exactly one primitive: a conditional write on a
single small object. Every backend that can offer put-if-absent and
compare-and-swap on one key can hold refs, and an authority that holds refs
needs nothing else.

The ref namespace and the commit graph follow git's shape, because git's
shape is right for this problem: branches advance, tags are permanent,
commits form a DAG with parents, and the reflog is a history of where a name
has pointed. The object encoding is not git's, for the reasons in
[`39-decision-register.md`](39-decision-register.md).

## Ref namespace

- **[REF-1]** A ref name MUST match `refs/<class>/<path>` where `<class>` is
  one of `heads`, `tags`, `notes`, `jobs`, `conflicts`, `derived`, and
  `<path>` is one or more
  non-empty segments of printable ASCII excluding `/`, `..`, control
  characters, and the characters `~^:?*[\`. Names are case-sensitive.
  *Gate:* `gate:ref-names`.
- **[REF-2]** `refs/heads/<path>` is a **branch**: it advances by
  compare-and-swap. `refs/tags/<path>` is a **tag**: it is written by
  put-if-absent and MUST NOT be changed or deleted except by a principal
  holding `admin` on it and never by an ordinary commit. A snapshot is a tag.
- **[REF-3]** `refs/notes/<path>` holds advisory sidecar refs (access
  profiles, derivation memos, completeness caches) whose loss MUST NOT affect
  correctness. `refs/jobs/<id>` holds tree-job checkpoints
  ([`32-tree-jobs.md`](32-tree-jobs.md)). `refs/conflicts/<ref>/<seq>`
  holds a commit whose merge into `<ref>` produced an unresolvable conflict
  value ([`20-consistency.md`](20-consistency.md)); it is a branch that
  advances only by resolution. `refs/derived/<path>` holds derivations
  ([`10-derived-data.md`](10-derived-data.md)) that are worth sharing by
  name, such as ruleset-derived realization roots
  ([`31-routing-rulesets.md`](31-routing-rulesets.md)); like `notes`, its
  loss MUST NOT affect correctness.
- **[REF-4]** `logs/refs/heads/<path>/<seq>` is the **reflog** of a branch:
  one immutable log record per sequence number, written by put-if-absent.
  The reflog is part of the namespace for reading but is not itself a ref.

## Ref record

A ref record is the canonical CBOR map defined in
`reference/terrane-v1.cddl` as `RefRecord`:

```text
commit        hash of the commit this ref names
seq           unsigned, strictly increasing per ref, 1 for the first write
writer_epoch  unsigned, fencing token for the current writer
home          locality label of the authority that owns this ref
policy        optional map: multi-writer policy, retention, conflicted flag
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
profile-pair  map: identity profile, chunk profile, tree-format version,
            recipe, conflicted flag, lease, required-property snapshot
packs       optional list of (pack id, locality) for packs first written by
            this commit
signature   detached signature over the preceding fields (23)
```

- **[REF-8]** A commit MUST name exactly one tree root. A commit produced by
  a merge MUST list `ours` first and `theirs` second in `parents`. A fold
  MUST record both ([`07-tree-algebra.md`](07-tree-algebra.md)).
- **[REF-9]** `profile-pair` MUST record the identity profile
  ([`04-content-model.md`](04-content-model.md) OBJ-8), the chunk profile
  ([`05-chunking.md`](05-chunking.md)), and the tree-format version in
  effect at the commit, and MUST set `conflicted=true` when the tree
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
  (3) write the reflog record `logs/refs/heads/<path>/<seq+1>` by
  put-if-absent; (4) compare-and-swap `refs/heads/<path>` from the record it
  read to the new record. A failure at any step MUST leave the ref
  unchanged. *Gate:* `gate:ref-advance-ordering`.
- **[REF-13]** Step (3) MUST use put-if-absent on the exact sequence number.
  A conflict at step (3) or (4) means another writer advanced the ref; the
  writer MUST re-read the ref, and then either fail (single-writer mode) or
  rebase by merge (multi-writer mode) and retry from step (2).
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
  `writer_epoch` MUST be the writing principal's current epoch.
- **[REF-20]** An **annotated tag** MAY carry, in its record's `policy`, a
  snapshot envelope: a signed statement binding the tag name, the commit, and
  arbitrary attestation data. The envelope format is `SnapshotEnvelope` in
  `reference/terrane-v1.cddl`.

## Reflog

- **[REF-21]** Every advance of a branch MUST leave a reflog record. The
  record MUST contain the new ref record, the previous commit hash, the
  principal, and a reason string (`commit`, `merge`, `fold`, `rollback`,
  `job-checkpoint`, `migrate`).
- **[REF-22]** Reflog records are garbage-collection roots for as long as
  the branch's `reflog_retain` property keeps them
  ([`08-properties.md`](08-properties.md)). Expiry removes the record; the
  commit it named becomes unreachable unless another root reaches it.
- **[REF-23]** Reading `logs/refs/heads/<path>/` MUST return records in
  sequence order. Gaps MUST be reported; a reader MUST NOT infer a gap means
  an advance did not occur.

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
  request the reflog from a given `seq` to fill what it missed.
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

An earlier generation of this design kept object records, chunk locations,
reference counts, aliases, pins, and job state in a transactional key-value
database and needed shared open packs with leases and a reaper to reclaim
them. Every one of those structures existed to coordinate mutation of
something other than a ref. Making every writer seal its own packs, making
every index and manifest immutable, and putting all mutability in refs
leaves exactly one coordination point, and that point fits in a single
conditional PUT on any bucket that supports one.
