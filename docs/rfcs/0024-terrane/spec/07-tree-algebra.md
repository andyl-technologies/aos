# 07 — Tree algebra

This file owns the operations on trees: how roots compose by reference, how
they split, how they are layered, compared, merged, filtered, and mapped, and
what each operation costs. It defines the semantics that make a namespace a
value: forking is one ref write, folding is a merge of what changed, and no
operation copies content. The encoding of trees is owned by
[`06-tree-format.md`](06-tree-format.md); the refs that name roots are owned
by [`09-refs-and-commits.md`](09-refs-and-commits.md).

## Model

A [tree](02-glossary.md#the-five-nouns) is a persistent, history-independent
Merkle map from path to entry. Two properties of the encoding make an algebra
possible:

1. **History independence.** Two trees with the same entries have the same
   root hash regardless of the sequence of operations that produced them. Any
   operation can therefore short-circuit on equal subtree hashes: equal hashes
   mean equal contents, with no walk required.
2. **Ordered keys.** Entries are sorted bytewise by path, so a directory's
   entries form one contiguous key range, and every operation is a walk of
   one or more cursors in key order.

Composition happens through the `tree` entry: an entry whose target is another
root. Keys inside a root are relative to that root, so grafting a root beneath
a path never rewrites keys. A tree is therefore a forest of roots, each root
being the unit of properties, authority, storage placement, and ownership
([`08-properties.md`](08-properties.md)).

Every operation below is defined on roots and produces roots. An operation
produces either a **virtual** composite, resolved lazily at lookup, or a
**materialized** root, a single prolly tree. Both forms have the same observable
namespace; they differ in cost and in whether the result has a single root
hash that can be sealed, indexed, or exposed by every surface.

## Operations

### Graft

`graft(parent, at, root)` produces a parent tree in which the entry at path
`at` is a `tree` entry targeting `root`.

- **[ALG-1]** `graft` MUST NOT rewrite any key of `root`. Its cost MUST be
  O(log n) in the size of `parent`: the nodes on the path to `at` are
  rewritten and nothing else. *Gate:* `gate:algebra-graft`.
- **[ALG-2]** If an entry already exists at `at`, `graft` MUST replace it. If
  entries exist beneath `at` in `parent` (that is, `at` is a directory with
  inline children), `graft` MUST fail with a structural error unless the
  caller requests replacement, in which case the inline subtree is removed
  from `parent` in the same operation.
- **[ALG-3]** Lookup of a path that crosses a `tree` entry MUST resolve the
  remainder of the path within the target root. Lookup cost across k nested
  roots is O(k log n). *See:* [`06-tree-format.md`](06-tree-format.md).

### Split

`split(root, prefix)` produces a standalone root containing every entry
beneath `prefix`, with keys made relative to `prefix`.

- **[ALG-4]** When `prefix` names a `tree` entry, `split` MUST return that
  entry's target root without reading or writing any node; its cost is O(1).
- **[ALG-5]** When `prefix` names an inline directory, `split` MUST produce a
  new root by a single range scan of `[prefix/, prefix0)`; its cost is
  O(size of subtree). The result's hash is a pure function of the subtree's
  entries by history independence.

### Flatten

`flatten(root, at)` inlines the root targeted by the `tree` entry at `at` into
the parent's key space, prefixing its keys with `at/`.

- **[ALG-6]** `flatten` MUST produce a root whose namespace is
  observationally identical to the grafted form. Its cost is O(size of the
  inlined root).
- **[ALG-7]** `flatten` MUST fail if the inlined root and the parent have
  different effective values for any property that this specification marks
  as a boundary property (`domain`, `store`, `acl`;
  [`08-properties.md`](08-properties.md)). A root MUST NOT be flattened across
  an authority boundary.

### Overlay

`overlay([top, ..., bottom])` produces a virtual composite whose lookup
consults each layer in order and returns the first entry found.

- **[ALG-8]** Creating an overlay MUST cost O(1) in the size of the layers; it
  records the ordered list of roots and nothing else.
- **[ALG-9]** Lookup in an overlay of L layers MUST cost O(L log n) worst case
  and MUST return the entry from the highest-precedence layer that has the
  key. A **whiteout** entry in a higher layer hides the key in every lower
  layer. Whiteouts are entries of type `whiteout` as defined in
  [`06-tree-format.md`](06-tree-format.md).
- **[ALG-10]** Directory listing of an overlay MUST be the ordered merge of the
  layers' ranges with higher layers winning on equal keys and whiteouts
  suppressing lower entries. Listing cost is O(L × entries in range).
- **[ALG-11]** An overlay MAY be materialized by `flatten`-style range
  merging. The materialized root MUST hash identically regardless of whether
  it was produced from the overlay or from an equivalent sequence of
  point updates.

### Diff

`diff(a, b)` produces the ordered set of changes that turn `a` into `b`.

- **[ALG-12]** `diff` MUST skip any subtree whose node hash is equal in both
  inputs. Its cost is O(delta × log n) where delta is the number of differing
  entries. *Gate:* `gate:algebra-diff`.
- **[ALG-13]** Each change MUST be one of: `added(path, entry)`,
  `removed(path, entry)`, `modified(path, old, new)`. Changes to a `tree`
  entry's target MUST be reported as a single `modified` change at the entry's
  path unless the caller requests descent, in which case `diff` recurses into
  the two targets.
- **[ALG-14]** `diff` output MUST be ordered by path and MUST be
  deterministic for a given pair of roots.

### Three-way merge

`merge(base, ours, theirs, policy)` produces a root combining the changes from
`base` to `ours` with the changes from `base` to `theirs`.

- **[ALG-15]** `merge` MUST be implemented as a three-cursor walk over the
  three inputs in key order and MUST skip any subtree whose hash is equal in
  all three inputs, or equal in `base` and one side (in which case the other
  side's subtree is taken whole). Its cost is O(delta × log n) where delta is
  the number of entries changed on either side. *Gate:*
  `gate:algebra-merge`.
- **[ALG-16]** For each key the merge MUST apply these rules, where `=` is
  entry equality including attributes and provenance:
  - `ours = theirs`: take `ours`.
  - `ours = base`: take `theirs`.
  - `theirs = base`: take `ours`.
  - otherwise: the key is **conflicted**; its result is a conflict value.
- **[ALG-17]** A merge MUST NOT fail because of a conflict. A conflicted key
  MUST produce a conflict value, an entry of type `conflict` that carries the
  ordered candidates `[base, ours, theirs]` (a candidate MAY be absent). This
  is the representation described for jj: a merge of trees is itself a tree
  whose entries may be sums of alternatives.
- **[ALG-18]** A merge policy resolves conflict values. The policy is named on
  the merging root's `merge` property ([`08-properties.md`](08-properties.md))
  or supplied by the caller. Registered policies are:
  - `prefer-ours`, `prefer-theirs`: take the named side.
  - `prefer-trusted`: take the candidate whose provenance satisfies the
    root's trust selector ([`23-provenance-and-trust.md`](23-provenance-and-trust.md));
    if both or neither do, fall through to the next policy in the list.
  - `prefer-newer`: take the candidate whose introducing commit has the
    later timestamp.
  - `keep-conflict`: leave the conflict value in the result.
  - `error`: fail the merge. This is the only policy that may fail.
  Policies MAY be listed; the first that resolves wins.
- **[ALG-19]** A root that contains a conflict value MUST be marked
  `conflicted` in its commit's profile ([`09-refs-and-commits.md`](09-refs-and-commits.md)).
  A surface MUST NOT expose a conflicted root unless the surface declares
  conflict support in its schema ([`26-surfaces.md`](26-surfaces.md)).
- **[ALG-20]** Merge MUST treat a `tree` entry whose target changed on both
  sides by recursing into the three targets when the entry's other fields are
  equal, and MUST otherwise treat the entry as an ordinary conflict.
- **[ALG-21]** A merge whose `base` equals `ours` MUST be a
  **fast-forward**: the result is `theirs` and no walk occurs.

### Filter and map

`filter(root, matcher)` produces a root containing only entries that satisfy
the matcher. `map(root, matcher, transform)` produces a root in which every
matched entry is replaced by the transform's output.

- **[ALG-22]** `filter` and `map` MUST accept matchers from the closed
  vocabulary of [`31-routing-rulesets.md`](31-routing-rulesets.md). Matchers
  that require content (`content_magic`) MUST be evaluated against the entry's
  stored classification attribute ([`10-derived-data.md`](10-derived-data.md))
  and MUST NOT fetch bytes during a `filter` or `map`; an entry with no such
  attribute does not match.
- **[ALG-23]** `filter` and `map` MUST cost O(matched × log n) when every
  matcher in the expression is prefix- or attribute-bounded, and O(n) when a
  matcher requires a full walk. An implementation MUST report which case
  applies for a given expression.
- **[ALG-24]** A `map` transform MUST be a pure function of the matched entry
  and the root's effective properties. Registered transforms are `remap`
  (replace the entry's content with a named object), `bind` (replace with a
  reference to a named external source), `strip-attr`, `set-attr`, and
  `retag-provenance`. Transforms are defined in
  [`31-routing-rulesets.md`](31-routing-rulesets.md).

### Set operations

The set operations are defined on entries keyed by path and derive from the
operations above.

- **[ALG-25]** `union(a, b)` MUST equal the materialized
  `overlay([a, b])`; `union` with `b` taking precedence is
  `overlay([b, a])`.
- **[ALG-26]** `difference(a, b)` MUST produce the root containing every
  entry of `a` whose key is absent from `b` or whose entry differs from
  `b`'s. It is `filter` of `diff(b, a)`'s `added` and `modified` changes.
- **[ALG-27]** `intersection(a, b)` MUST produce the root containing every
  entry present and equal in both. All three MUST skip equal subtrees and
  cost O(delta × log n).

## Virtual and materialized composites

- **[ALG-28]** Every composite (`overlay`, `graft`, `filter`, `map`, `merge`)
  MUST be expressible as a **recipe**: a canonical encoding of the operation
  and its input root hashes, as defined in `reference/terrane-v1.cddl`. A
  recipe's hash identifies the composite.
- **[ALG-29]** An implementation MUST be able to materialize any composite
  into a single root and MUST record the recipe on the resulting commit's
  profile so the root can be verified by recomputation.
- **[ALG-30]** An implementation SHOULD memoize materialized roots by recipe
  hash in the derived-data store ([`10-derived-data.md`](10-derived-data.md)),
  so that re-deriving a composite with the same inputs costs one lookup.
- **[ALG-31]** A virtual composite MUST NOT be sealed, indexed, or exposed
  through a surface that requires a single root hash in its schema. Such
  surfaces MUST request materialization.

The rule of thumb for choosing between a `tree` entry and inline entries:
mount where authority changes, inline everywhere else. A huge flat directory
benefits from prolly chunking and lives inline; a boundary of ownership,
tenancy, or storage class is a `tree` entry so it can be grafted, split,
and governed in O(1).

## Fork and fold

Fork and fold are the branch operations expressed in tree algebra; their ref
mechanics are in [`09-refs-and-commits.md`](09-refs-and-commits.md).

- **[ALG-32]** A **fork** of ref `P` at sequence `N` MUST create a ref whose
  first commit has tree root equal to `P@N`'s root and whose parent is `P@N`.
  No tree node is read or written. *Gate:* `gate:algebra-fork`.
- **[ALG-33]** A **fold** of child ref `C` into parent ref `P` MUST compute
  `merge(base, ours, theirs)` with `base` = the commit `C` was forked from,
  `ours` = `P`'s current commit, and `theirs` = `C`'s current commit, and
  MUST record both `ours` and `theirs` as parents of the resulting commit.
  When `P` has not moved since the fork, the fold MUST be a fast-forward.
- **[ALG-34]** A fold MUST be restricted to the roots the folding principal
  may commit ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)).
  Entries outside those roots MUST be excluded from `theirs` before the merge,
  and their exclusion MUST be reported.
- **[ALG-35]** After a successful fold the child ref SHOULD be retired: either
  deleted or converted to a tag, per the child's `retain` property.

### The continuous-integration flow (informative)

The flow that motivated fork and fold:

1. A job forks the baseline branch at sequence N. Its token can commit only
   its own ref. Its view already contains everything the baseline had.
2. The job uploads new chunks and manifests and commits to its own ref,
   possibly many times.
3. On acceptance, a trusted principal folds the job's ref into the baseline:
   `merge(baseline@N, baseline@now, job@head)`. Only differing subtrees are
   visited. Untrusted provenance is resolved by `prefer-trusted`, and the
   fold's commit is signed by the trusted principal.
4. The job's ref is retired. Nothing was copied; the baseline's new root
   shares every unchanged node with its previous root and with the job's.

## Complexity summary

| Operation | Cost | Output form |
| --- | --- | --- |
| `graft` | O(log n) | materialized |
| `split` at `tree` entry | O(1) | existing root |
| `split` of inline directory | O(subtree) | materialized |
| `flatten` | O(subtree) | materialized |
| `overlay` create | O(1) | virtual |
| `overlay` lookup | O(L log n) | — |
| `diff` | O(delta log n) | change set |
| `merge` | O(delta log n) | materialized |
| `filter`, `map` | O(matched log n) or O(n) | virtual or materialized |
| `union`, `difference`, `intersection` | O(delta log n) | materialized |
| fork | O(1) | ref |
| fold | O(delta log n) | commit |

Here n is the number of entries in the largest input and delta is the number
of differing entries; log n is the tree height.

## Interactions

- [`06-tree-format.md`](06-tree-format.md) defines the `tree`, `whiteout`,
  and `conflict` entry types and the node boundary function whose history
  independence every operation relies on.
- [`08-properties.md`](08-properties.md) defines the boundary properties that
  `flatten` respects and the `merge` property that names a policy.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines how fork and
  fold move refs and record parents.
- [`10-derived-data.md`](10-derived-data.md) holds recipe memos and the
  classification attributes that `filter` and `map` consult.
- [`31-routing-rulesets.md`](31-routing-rulesets.md) defines the matcher and
  transform vocabulary.
- [`26-surfaces.md`](26-surfaces.md) defines which surfaces accept virtual or
  conflicted roots.

## Informative: why a full-path key with `tree` entries

A tree keyed by full path gives contiguous directory ranges and O(delta)
diff and merge, but grafting by key rewrite would be O(subtree). A tree of
per-directory nodes grafts in O(1) but makes a large flat directory a single
node rewritten on every change. The `tree` entry takes the O(1) graft from the
second design and the chunked, history-independent ranges from the first, at
the price of a nested lookup across roots. See
[`39-decision-register.md`](39-decision-register.md).
