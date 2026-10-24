# 32 — Tree jobs

This file owns the single primitive through which any program iterates,
annotates, verifies, or rewrites a tree: the tree job. Scrub, garbage
collection marking, backfill of a new property, reindexing, content
classification, compaction, warming, and user workloads are all tree jobs.
They differ in the filter they apply and the function they run, not in how
they interact with the store.

## Model

A [tree](02-glossary.md#the-five-nouns) is an ordered map from path to
entry, stored as prolly-tree nodes whose sizes are known. That structure gives
three things for free, and the job primitive is built on exactly those three:

1. **Shards.** Any tree can be cut into `n` key ranges of roughly equal
   weight by walking internal nodes and summing leaf weights. No job table or
   coordinator is needed to divide work.
2. **Cursors.** Keys are totally ordered, so a job's progress within a shard
   is one key: the last key it processed. A restarted worker resumes at that
   key.
3. **Commits.** A job's results are ordinary tree changes. They are committed
   on a job branch forked from the target and folded back by
   [merge](07-tree-algebra.md). Concurrent writers to the target and the job
   never block each other, and a crashed job resumes from its branch.

The fourth element is **follow**: a job that watches a branch and, on each new
commit, processes only `diff(previous, new)`. A backfill over an existing
tree and a steady-state maintainer of a live branch are therefore the same
program. The first run processes the whole tree; every later run processes a
delta.

Derived attributes computed from content are keyed by object hash in the
[side table](10-derived-data.md), so a job that computes a hash or a
classification does the work once per distinct object, not once per entry or
once per view. A new view forked from an old one is already complete for
every property the old one satisfied.

```text
job = (target, filter, function, shards, follow?)

for shard in shards(target.root, n):
    cursor = resume(job, shard) or shard.start
    for entry in iterate(target.root, shard, from=cursor, where=filter):
        result = function(entry)          # may read content, may write attrs
        stage(result)
        if stage.size >= checkpoint_size:
            checkpoint()                  # commit on refs/jobs/<id>
            fold_if_due()                 # merge into target
    checkpoint(); fold()
```

## Job identity and refs

- **[JOB-1]** A tree job MUST be identified by a job id that is unique within
  a store, and its state MUST be carried by a branch named
  `refs/jobs/<job-id>` whose first commit is a fork of the target commit the
  job started from. *Gate:* `gate:job-ref-lifecycle`. *See:* §Model.
- **[JOB-2]** A job branch commit MUST record, in the commit's profile, the
  job's target ref, filter, function identifier, shard count, and the cursor
  of every shard at the time of the checkpoint. *Gate:*
  `gate:job-ref-lifecycle`.
- **[JOB-3]** A job MUST be resumable from its branch alone: a worker given
  only the store and the job id MUST be able to continue from the recorded
  cursors without any other state. *Gate:* `gate:job-resume`.
- **[JOB-4]** Job branches MUST be subject to the same
  [authorization](22-authentication-and-authorization.md) as any other
  branch. Creating `refs/jobs/<id>` requires `fork` on the target; folding
  requires `commit` on the target.
- **[JOB-5]** A job branch SHOULD be deleted when the job completes or is
  cancelled, after its final fold. An implementation MAY retain job branches
  for a configured period for audit. Retained job branches are garbage
  collection roots like any ref ([`17-garbage-collection.md`](17-garbage-collection.md)).

## Sharding

- **[JOB-6]** `shards(root, n)` MUST return `n` contiguous, non-overlapping
  key ranges whose union is the whole key space of `root`, computed from
  prolly-tree node weights without reading leaf entries. *Gate:*
  `gate:job-shards`. *See:* [`06-tree-format.md`](06-tree-format.md).
- **[JOB-7]** The weight of a shard MUST NOT exceed twice the mean shard
  weight when `n` is at most the number of leaf nodes. *Gate:*
  `gate:job-shards`.
- **[JOB-8]** Shards MUST be stable for a fixed `(root, n)`: two calls MUST
  return identical ranges. Ranges MAY differ between different roots of the
  same branch; a worker resuming after the target advanced re-derives shards
  against the job's fork commit, not the live head.
- **[JOB-9]** A shard MUST be processable by a worker that holds no lock. Two
  workers processing one shard concurrently MUST produce the same result
  (idempotency, [JOB-15]); the implementation SHOULD avoid it by assigning
  shards to workers through the job branch's cursor records.

## Iteration and filters

- **[JOB-10]** `iterate(root, range, from, where)` MUST yield entries in key
  order starting at `from`, applying `where` before yielding. It MUST NOT
  fetch content for entries the filter rejects on metadata alone.
- **[JOB-11]** The filter vocabulary MUST include at least: `missing(attr)`,
  `has(attr)`, `attr(name) = value`, `type in {file, dir, symlink, tree}`,
  `path_prefix`, `path_glob`, `object_in(set)`, `modified_since(commit)`,
  and the boolean combinators `all`, `any`, `not`. Filters are the matcher
  vocabulary of [`31-routing-rulesets.md`](31-routing-rulesets.md) plus the
  attribute and history predicates listed here.
- **[JOB-12]** Iteration across a `tree` entry MUST descend into the
  referenced root only when the job's target includes that root's properties
  (inherited [`08-properties.md`](08-properties.md)) and the job's token
  grants `read` on it. Otherwise the `tree` entry is yielded as a single entry
  and not descended.
- **[JOB-13]** A cursor MUST be the last key fully processed in a shard. A
  worker that crashes after processing an entry but before recording a
  cursor MUST reprocess that entry on resume; [JOB-15] makes this safe.

## Functions, staging, and checkpoints

- **[JOB-14]** A job function MUST be one of: `annotate` (write entry or
  object attributes), `verify` (read content, compare against the entry's
  hashes, report), `transform` (produce a replacement entry or subtree via
  the [tree algebra](07-tree-algebra.md)), `fetch` (bring content into a
  tier without changing the tree), or `visit` (yield entries to a caller
  without writing). New function kinds are added by revision of this file.
- **[JOB-15]** Every job function MUST be idempotent with respect to its
  inputs: applying it twice to the same entry and object MUST leave the tree
  and side table in the same state as applying it once. *Gate:*
  `gate:job-idempotent`.
- **[JOB-16]** Attributes derived from content MUST be written to the
  per-object side table keyed by object hash, and MUST be looked up there
  before any content is read. A job MUST NOT recompute a derived attribute
  already present for an object hash. *Gate:* `gate:job-memo`. *See:*
  [`10-derived-data.md`](10-derived-data.md).
- **[JOB-17]** Staged results MUST be checkpointed as a commit on the job
  branch at least every `checkpoint_size` entries or `checkpoint_interval`
  seconds, whichever comes first; both are job parameters with implementation
  defaults. *Gate:* `gate:job-resume`.
- **[JOB-18]** A checkpoint commit MUST be a fast-forward of the job branch.
  Job branches have exactly one writer, fenced by the writer epoch of
  [`09-refs-and-commits.md`](09-refs-and-commits.md); a worker whose epoch is
  superseded MUST stop.

## Folding into the target

- **[JOB-19]** A fold MUST be a three-way merge with base = the job's fork
  commit (or the last folded commit), ours = the target head, theirs = the
  job branch head, and MUST update the target ref by conditional write. On a
  lost conditional write the fold MUST re-read the target and retry the
  merge. *Gate:* `gate:job-fold`.
- **[JOB-20]** A fold MUST NOT fail on entries changed by both sides when the
  job function was `annotate`: the merge policy for attributes written by a
  job is "attribute-wise union, job value wins for the attributes the job
  owns, other side wins for everything else". For `transform` jobs the
  target's merge policy applies and a conflict value is recorded as in
  [`07-tree-algebra.md`](07-tree-algebra.md).
- **[JOB-21]** After a successful fold the job MUST record the folded target
  commit as its new merge base so subsequent folds are O(delta).
- **[JOB-22]** Fold frequency SHOULD be bounded by `fold_interval` and
  `fold_size` job parameters so that a long backfill lands in bounded
  increments and the target's reflog grows proportionally to work done, not
  to entries touched.

## Follow mode

- **[JOB-23]** A job with `follow` set MUST, after its initial pass, watch the
  target ref ([`18-protocol.md`](18-protocol.md) watch) and, for each new
  commit, process exactly the entries in `diff(previous_head, new_head)` that
  match the filter, where `previous_head` is the last commit the job
  processed. *Gate:* `gate:job-follow`.
- **[JOB-24]** A following job MUST tolerate commits it did not produce
  landing between its own folds, and MUST NOT reprocess entries it has
  already annotated unless the entry's object changed.
- **[JOB-25]** A following job that falls behind by more than
  `max_lag_commits` SHOULD collapse its pending deltas into one diff between
  the last processed commit and the current head.

## Status and completeness

- **[JOB-26]** Job status MUST be derivable from the job branch alone: the
  fork commit, the latest checkpoint, per-shard cursors, counts of entries
  processed, skipped, and failed, and the last fold. A status query MUST NOT
  require the worker to be running.
- **[JOB-27]** When a job's purpose is to satisfy a property, the property's
  [completeness](08-properties.md) MUST be reported alongside the job status
  and MUST reach 100% when the job completes without failures.
- **[JOB-28]** Per-entry failures MUST be recorded as an attribute on the
  entry in the job branch (`job.failed = <job-id>:<reason>`) so that a rerun
  with filter `attr(job.failed)` retries exactly the failed set. A job MUST
  NOT abort on a per-entry failure unless `fail_fast` is set.

## Cancellation and cleanup

- **[JOB-29]** Cancelling a job MUST advance the job branch's writer epoch so
  any running worker stops at its next checkpoint, then MUST either fold the
  last checkpoint (`cancel --fold`) or discard it (`cancel --discard`), then
  delete the job branch per [JOB-5].
- **[JOB-30]** Job branches whose last checkpoint is older than
  `abandoned_after` and whose writer has not renewed its epoch MUST be listed
  by status as abandoned and MAY be cleaned up by a maintenance job using the
  same primitive.

## Built-in jobs

The following jobs are defined by other files and MUST be implemented as tree
jobs using this primitive:

| Job | Function | Filter | Defined in |
| --- | --- | --- | --- |
| scrub | `verify` | all files | [`15-redundancy.md`](15-redundancy.md) |
| GC mark | `visit` | all | [`17-garbage-collection.md`](17-garbage-collection.md) |
| backfill | `annotate` | `missing(attr)` | [`08-properties.md`](08-properties.md) |
| reindex | `annotate` (index tree) | `has(attr)` | [`10-derived-data.md`](10-derived-data.md) |
| classify | `annotate` | `missing(class)` | [`10-derived-data.md`](10-derived-data.md) |
| compaction | store-level, driven by `visit` over live packs | — | [`17-garbage-collection.md`](17-garbage-collection.md) |
| warm | `fetch` | profile or all | [`19-tiering-and-topology.md`](19-tiering-and-topology.md) |
| import | `transform` | — | [`33-migrations.md`](33-migrations.md) |

- **[JOB-31]** Built-in jobs MUST NOT use any store or tree access path that a
  user-defined job cannot use through the public interface. *Gate:*
  `gate:job-uniform-access`.

## Access from inside an exposure

- **[JOB-32]** A process inside a writable or read-only exposure MUST be able
  to run `visit` and `annotate` jobs over the exposed view through the
  exposure's control socket ([`27-surface-fuse.md`](27-surface-fuse.md)),
  using the exposure's token and no other credential. The job sees exactly
  the roots that token can read and writes only where it can commit.
- **[JOB-33]** Jobs started through an exposure MUST run outside the
  exposure's resource limits only if the token carries `admin` on the target;
  otherwise they run within the exposure's accounting.

## Command shape (informative)

```text
terrane property set refs/heads/main hashes=[blake3,sha256]
terrane job run backfill --target refs/heads/main --property hashes --shards 32
terrane job status <job-id>
terrane job list --abandoned
terrane job cancel <job-id> --fold
terrane job run scrub --target refs/tags/release-2026-09 --shards 8
terrane job run visit --target refs/heads/main --where 'type=file and missing(class)' \
    --exec ./classify
```

## Interactions

- [`07-tree-algebra.md`](07-tree-algebra.md) supplies diff and merge.
- [`08-properties.md`](08-properties.md) and
  [`10-derived-data.md`](10-derived-data.md) define what backfill and reindex
  produce and where derived attributes live.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) supplies writer epochs
  and conditional writes for job branches.
- [`17-garbage-collection.md`](17-garbage-collection.md) treats job branches
  as roots and implements mark as a job.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)
  governs job branch creation and folding.
- [`33-migrations.md`](33-migrations.md) builds every migration on this
  primitive.
