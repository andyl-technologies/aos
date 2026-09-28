# 20 — Consistency

This file owns the consistency model: what a reader can assume about what it
sees, what a writer can assume about what it wrote, and how those guarantees
are chosen. It specifies the separation between local POSIX consistency
inside an exposure and distributed consistency at commits, the writer
modes, durability levels, single-writer fencing, multi-writer merge
policy, reader modes, the consistency table, the errors a POSIX caller
receives, and the control interface inside a mount.

## Overview

Terrane draws one line and puts every consistency question on one side of
it or the other. Inside a writable exposure, the filesystem is local: writes
go to a private upper on the host, and every POSIX guarantee the host
filesystem gives is preserved unchanged. Across exposures, machines, and
regions, the only event is a commit: a new tree root bound to a ref by a
conditional write. Nothing is visible to anyone else before a commit and
everything in the commit is visible atomically after it.

The line is drawn there because it is the only place where the guarantees
on both sides can be strong. A local filesystem can be fully POSIX because
one kernel owns it. A commit can be linearizable because one authority
owns each ref. Anything in between, such as per-file remote writes with
shared readers, would be neither, and this specification does not offer
it.

The user's choices are therefore not "how consistent" but "when do commits
happen" and "how durable is a commit". Both are properties an exposure or a
root carries, and both bubble up to a POSIX writer through the one verb
POSIX has for durability: `fsync`.

## Local consistency inside an exposure

- **[CONS-1]** A writable exposure MUST direct every mutation to a private
  upper that no other exposure can observe. Reads within the exposure MUST
  observe the exposure's own prior writes immediately. *Gate:*
  `gate:cons-local`. *See:* [`27-surface-fuse.md`](27-surface-fuse.md).
- **[CONS-2]** Within an exposure, the semantics of `write`, `rename`,
  `unlink`, `truncate`, `mmap`, advisory and mandatory locks, and directory
  operations MUST be those of the host filesystem that backs the upper. An
  implementation MUST NOT weaken them and MUST NOT strengthen them in a way
  that a program could come to rely on. *Gate:* `gate:cons-local`.
- **[CONS-3]** Nothing written to an upper MUST become visible through any
  other exposure, ref, or protocol response before a commit that includes
  it has been acknowledged. *Gate:* `gate:cons-commit-visibility`.

## Commits

- **[CONS-4]** A commit MUST be atomic: a reader that observes the ref
  after the commit MUST observe every entry of the new tree, and a reader
  that observes the ref before the commit MUST observe none. There MUST be
  no state in which a subset of the commit's changes is visible. *Gate:*
  `gate:cons-commit-visibility`.
- **[CONS-5]** A commit MUST be ordered per ref by the ref's sequence
  number, and `CompareAndSwapRef` MUST be linearizable at the ref's home
  authority. *Gate:* `gate:ref-cas`.
- **[CONS-6]** A commit MUST NOT be acknowledged before every pack it
  introduces, every meta pack it introduces, and the ref write are durable
  at the root's effective durability level (§Durability). *Gate:*
  `gate:cons-durability`.

## Writer modes

An exposure's writer mode says when the upper is turned into commits.

| Mode | Commit happens | `fsync`, `fdatasync`, `syncfs` mean |
| --- | --- | --- |
| `manual` | when the SDK, the CLI, or the control directory requests it, or at lease end | local durability of the upper only |
| `periodic` | every `interval` or on quiescence, as fast-forward commits | local durability of the upper only |
| `sync` | on every `fsync`, `fdatasync`, and `syncfs` | a commit including the synced file, acknowledged at the root's durability level |

- **[CONS-7]** Every writable exposure MUST have a writer mode of `manual`,
  `periodic`, or `sync`, defaulting to `manual`. *Gate:*
  `gate:cons-writer-modes`.
- **[CONS-8]** In `manual` and `periodic` modes, `fsync` and its relatives
  MUST return once the host filesystem reports the upper durable and MUST
  NOT initiate a commit. *Gate:* `gate:cons-writer-modes`.
- **[CONS-9]** In `periodic` mode the implementation MUST commit at most
  once per `interval` (default 30 seconds) and MUST also commit when no
  write has occurred for `quiescence` (default 5 seconds), whichever comes
  first, provided the upper has changed. *Gate:* `gate:cons-writer-modes`.
- **[CONS-10]** In `sync` mode, `fsync` and `fdatasync` on a file MUST NOT
  return success until a commit whose tree includes the file's current
  content has been acknowledged per CONS-6. `syncfs` MUST commit the entire
  upper. The commit MAY include other dirty files. *Gate:*
  `gate:cons-sync-fsync`.
- **[CONS-11]** A commit produced by any writer mode MUST be a complete
  tree: the implementation MUST NOT commit a subset of the upper's changes
  that would leave the tree in a state no program wrote. A file being
  written at commit time is included at whatever content the upper holds
  when the commit's snapshot of the upper is taken. *Gate:*
  `gate:cons-commit-visibility`.
- **[CONS-12]** A commit MUST snapshot the upper atomically with respect to
  ongoing writes where the host filesystem provides a snapshot primitive,
  and otherwise MUST quiesce writes for the duration of the tree walk.
  The chosen mechanism MUST be reported in exposure status. *Gate:*
  `gate:cons-commit-visibility`.
- **[CONS-13]** At lease end or exposure teardown in `manual` mode, the
  implementation MUST either commit the upper or retain it for later commit
  according to the exposure's `on-release` policy, and MUST NOT discard an
  uncommitted upper without an explicit `discard` policy. *Gate:*
  `gate:cons-writer-modes`.

## Durability

- **[CONS-14]** Every root MUST have an effective `durability` property with
  one of the values `local`, `zone`, `region`, or `regions(k)`. *Gate:*
  `gate:cons-durability`. *See:* [`08-properties.md`](08-properties.md).
- **[CONS-15]** The meaning of each level is:
  `local`, durable on the committing tier's own storage; `zone`, durable on
  at least two stores in the committing tier's zone or on the zone's
  authority; `region`, durable at the root's home authority; `regions(k)`,
  durable at the home and at `k-1` further regions named by the root's
  `replicate` policy. A commit MUST NOT be acknowledged below its root's
  level. *Gate:* `gate:cons-durability`.
- **[CONS-16]** A commit's acknowledgment MUST carry the durability level
  actually achieved, which MUST be at least the required level and MAY be
  higher. *Gate:* `gate:cons-durability`.

## Single writer and fencing

- **[CONS-17]** A ref MUST have at most one active writer by default. The
  writer holds the ref's current writer epoch; every `CompareAndSwapRef`
  carries it; a write with a stale epoch MUST be rejected. *Gate:*
  `gate:cons-fencing`. *See:*
  [`09-refs-and-commits.md`](09-refs-and-commits.md).
- **[CONS-18]** A writer acquires the epoch by a `CompareAndSwapRef` that
  increments it. A writable exposure MUST acquire the epoch when it is
  created and MUST NOT accept writes into its upper before it holds it.
  *Gate:* `gate:cons-fencing`.
- **[CONS-19]** Once an exposure's epoch has been superseded, the exposure
  is fenced. A fenced exposure MUST reject every subsequent write with
  `EROFS`, MUST fail every pending and future `fsync` with `EROFS`, MUST
  retain its upper for inspection, and MUST NOT ever commit again. Fencing
  is permanent for that exposure. *Gate:* `gate:cons-fencing`.
- **[CONS-20]** An exposure whose lease has expired MUST be treated as
  fenced. *Gate:* `gate:cons-fencing`.

## Multiple writers

- **[CONS-21]** A ref MAY be configured `writers=many`, in which case
  epochs are per writer rather than per ref and a `CompareAndSwapRef` that
  loses MUST be retried by the writer after a three-way merge of its commit
  against the ref's new value, using the merge policy named by the root's
  `merge` property. *Gate:* `gate:cons-multiwriter`. *See:*
  [`07-tree-algebra.md`](07-tree-algebra.md).
- **[CONS-22]** Under `writers=many`, the implementation MUST bound
  auto-rebase attempts (default 8) and MUST surface exhaustion as a commit
  failure, not as an indefinite retry. *Gate:* `gate:cons-multiwriter`.
- **[CONS-23]** Under `writers=many`, a merge that yields a conflict value
  the policy cannot resolve MUST fail the commit. In `sync` mode this is
  the one condition under which `fsync` fails with `EBUSY`. In other modes
  the failure is reported through the control directory and the commit is
  retained as an unmerged branch under `refs/conflicts/<ref>/<seq>` for
  later resolution. *Gate:* `gate:cons-multiwriter`.

## Errors reaching POSIX callers

The mapping from outcomes to `errno` values is normative in
[`reference/errno-mapping.md`](reference/errno-mapping.md). The rules below
govern how the mapping is applied.

- **[CONS-24]** When `fsync` fails for any reason other than `EINTR`, the
  file MUST remain in a failed state and every later `fsync` of that file
  MUST return the same error until a commit that includes the file's
  current content succeeds. An implementation MUST NOT clear a failure
  merely because the error was reported once. *Gate:*
  `gate:cons-fsync-sticky`.
- **[CONS-25]** A write that cannot be accepted into the upper because the
  exposure's reservation is exhausted MUST fail with `EDQUOT`. A write
  whose commit would exceed a root quota MUST be accepted into the upper
  and the later commit MUST fail with `ENOSPC` per CONS-24. *Gate:*
  `gate:cons-errors`.
- **[CONS-26]** A commit that fails because packs could not be uploaded or
  the ref could not be written MUST be reported as `EIO` on `fsync` in
  `sync` mode and through the control directory in every mode, with the
  protocol error retained for inspection. *Gate:* `gate:cons-errors`.
- **[CONS-27]** An implementation MUST NOT report success for `fsync` in
  `sync` mode before the acknowledgment required by CONS-10 and MUST NOT
  report success for `close` as if it implied durability. *Gate:*
  `gate:cons-sync-fsync`.

## Reader modes

An exposure's reader mode says which commit it shows.

| Mode | Shows | Guarantee |
| --- | --- | --- |
| `pinned` | one commit for the life of the exposure | strong; never changes |
| `follow` | the branch head, switched atomically per commit | bounded staleness, reported |

- **[CONS-28]** A `pinned` exposure MUST show exactly the tree of one
  commit, identified at creation, for its entire life. *Gate:*
  `gate:cons-reader-modes`.
- **[CONS-29]** A `follow` exposure MUST switch from one commit's tree to
  the next as a single atomic namespace replacement, such that no path
  resolution observes entries from two commits. The switch MUST be
  implemented by preparing the new tree and replacing the mount beneath the
  old one, or by an equivalent primitive of the surface, per
  [`27-surface-fuse.md`](27-surface-fuse.md) and
  [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md).
  *Gate:* `gate:cons-follow-atomic`.
- **[CONS-30]** File descriptors and mappings open at the time of a switch
  MUST continue to refer to the old commit's content. A switch is a change
  for new path resolution, not a revocation. *Gate:*
  `gate:cons-follow-atomic`.
- **[CONS-31]** A `follow` exposure MUST report the commit it currently
  shows and the staleness bound of the ref read that selected it, and MUST
  NOT switch to a commit older than the one it shows. *Gate:*
  `gate:cons-reader-modes`.
- **[CONS-32]** A `follow` exposure MUST NOT switch while a commit is being
  prepared from its own upper, if it is also writable, until that commit
  has been acknowledged or has failed. *Gate:* `gate:cons-reader-modes`.

## The consistency table

The table is normative. Each row names an operation, where it is performed,
and the guarantee the caller receives.

| Operation | Performed at | Guarantee |
| --- | --- | --- |
| read chunk, object, tree node, commit | any tier | strong; content-addressed, verified on admit |
| read ref, `freshness=any` | any tier | may be stale; staleness reported |
| read ref, `freshness=bounded(d)` | any tier | stale by at most `d`, else `UNAVAILABLE` |
| read ref, `freshness=linearizable` | home authority | linearizable |
| commit, merge, tag, ref write | home authority | linearizable per ref |
| fork | any tier | strong; reads a specific commit, then writes a new ref at its home |
| read inside a writable exposure | the exposure | POSIX, read-your-writes |
| read across exposures of one ref | each exposure | commit-granular; each shows some commit of the ref |

- **[CONS-33]** An implementation MUST provide every guarantee in the
  consistency table and MUST NOT advertise a stronger guarantee for any row.
  *Gate:* `gate:cons-table`.

## The control interface

A writable or followable exposure carries a control interface inside the
mount so that a program with no network access and no credentials of its
own can observe and drive commits through the exposure's authority.

- **[CONS-34]** Every FUSE-realized exposure MUST present a `.terrane`
  directory at its root containing at least: `commit` (the commit id
  shown), `ref` (the ref followed, if any), `status` (writer mode, reader
  mode, dirty entry count, last commit result, fencing state, staleness),
  and `control` (a write-only file accepting commands). Other surfaces
  SHOULD present the same interface where the surface permits.
  *Gate:* `gate:cons-control`.
- **[CONS-35]** Writing a command to `control` MUST perform the command
  under the exposure's own token and MUST report the result in `status`.
  The commands are `commit [message]`, `tag <name>`, `fork <name>`,
  `sync`, and `discard`. `discard` MUST require the `on-release=discard`
  policy or an `admin` grant. *Gate:* `gate:cons-control`.
- **[CONS-36]** The values in `commit`, `ref`, and `status` MUST also be
  exposed as extended attributes on the mount root, named
  `user.terrane.commit`, `user.terrane.ref`, and `user.terrane.status`, for
  programs that prefer `getxattr` to file reads. *Gate:*
  `gate:cons-control`.
- **[CONS-37]** The `.terrane` directory MUST NOT be included in any commit
  and MUST NOT be visible in tree listings obtained through the protocol.
  *Gate:* `gate:cons-control`.

## Out of scope

- **[CONS-38]** This specification does not provide sub-commit shared
  consistency: two exposures of one ref never observe each other's
  uncommitted writes, and there is no distributed lock, lease, or
  record-level coherence between them. A workload that requires such
  semantics MUST use a live native filesystem outside Terrane's tree, and
  an implementation MUST NOT emulate them. *See:*
  [`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md).

## Interactions

- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines the ref value,
  sequence, and epoch that fencing and CAS rely on.
- [`18-protocol.md`](18-protocol.md) carries `freshness` and the CAS
  precondition.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) defines home,
  which fixes where linearizable operations run.
- [`07-tree-algebra.md`](07-tree-algebra.md) defines the merge used by
  auto-rebase.
- [`08-properties.md`](08-properties.md) registers `durability`, `writers`,
  `merge`, and `on-release`.
- [`27-surface-fuse.md`](27-surface-fuse.md) and
  [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md) realize
  the upper, the atomic switch, and the control directory.
- [`reference/errno-mapping.md`](reference/errno-mapping.md) is the
  normative error table.

## Informative: what a program experiences

A build in `manual` mode writes thousands of files, calls `fsync` on a few,
and exits. Every `fsync` returned when the host disk had the bytes; nothing
left the machine. The orchestrator then writes `commit` to `.terrane/control`
and the whole result becomes one commit on the job's branch.

A service in `sync` mode appends a record and calls `fdatasync`. The call
returns after a small commit containing the file has been acknowledged at
`durability=region`, typically tens of milliseconds within a region. If the
region's authority is unreachable, `fdatasync` returns `EIO`, every later
`fdatasync` of that file returns `EIO` until one succeeds, and the record is
still on local disk in the upper.

A consumer in `follow` mode on `refs/heads/master` sees the fold of a merged
pull request as a single switch. A process that had a shared library open
keeps the old copy; the next `exec` gets the new one.
