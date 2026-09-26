# 10 — Derived data

This file owns everything computed from content rather than supplied by a
writer: per-object attributes such as additional content hashes and
classifications, and **derivations**, roots computed from a recipe and
memoized by the recipe's hash. Index trees and realization roots are the
two named kinds of derivation. Derived data is always recomputable from the tree and the
chunks; it is stored so that it is computed once per distinct object rather
than once per entry, per view, or per reader. Which attributes a root
requires is governed by [`08-properties.md`](08-properties.md); how gaps are
closed is governed by [`32-tree-jobs.md`](32-tree-jobs.md).

## Model

An [entry](02-glossary.md#the-five-nouns) carries attributes. Some are
supplied by the writer and are part of the entry's identity (mode bits,
size, symlink target). Others are functions of the object's bytes alone:
its digest under a second algorithm, whether it is an ELF executable, its
git blob identifier. These **derived attributes** are keyed by object hash in
a **side table** of content-addressed meta objects, so that a library
referenced from ten thousand entries in a thousand views has its SHA-256
computed once, and a view forked from a complete parent is complete at
birth.

A **derivation** is a root computed by evaluating a recipe
([`07-tree-algebra.md`](07-tree-algebra.md) ALG-28) over one or more input
roots. Its identity is the recipe hash; its value is the resulting root
hash; it is memoized in the side table so that the same recipe over the
same inputs is evaluated once, and it can always be verified or rebuilt by
re-evaluating the recipe. Everything derived from a tree is a derivation:
an **index tree** is the derivation `index(root, attribute)`, a tree keyed
by attribute value whose entries point at object hashes; a **realization
root** is the derivation a ruleset produces when a view is realized
([`31-routing-rulesets.md`](31-routing-rulesets.md)); a materialized
composite is the derivation of its `overlay`, `graft`, `filter`, `map`, or
`merge` recipe. There is one memo table and one verification rule for all
of them. Lookup by a secondary hash is a range lookup in an index tree.

## Side table

- **[DRV-1]** A derived attribute record MUST be a meta object in the
  `terrane-attr-v1` identity domain ([`04-content-model.md`](04-content-model.md))
  whose key is `(object hash, attribute name)` and whose encoding is
  `AttrRecord` in `reference/terrane-v1.cddl`. The record MUST carry the
  attribute value, the name and version of the function that produced it,
  and the provenance of the producer. *Gate:* `gate:derived-attr-record`.
- **[DRV-2]** A derived attribute MUST be a pure function of the object's
  plaintext bytes and the function version. Two producers computing the same
  attribute for the same object MUST produce identical records; an
  implementation MAY verify a record by recomputation and MUST quarantine a
  record that fails verification.
- **[DRV-3]** Side-table records are stored in meta packs
  ([`12-pack-format.md`](12-pack-format.md)) and are garbage-collected when
  no reachable entry references an object with that hash
  ([`17-garbage-collection.md`](17-garbage-collection.md)).
- **[DRV-4]** An entry MAY carry a derived attribute inline in the tree node
  in addition to the side table, so that readers need no side-table lookup
  for hot attributes. When both exist they MUST agree; the inline copy is
  the one a `filter` or `map` consults ([`07-tree-algebra.md`](07-tree-algebra.md)).
- **[DRV-5]** Lookup of a derived attribute for an object MUST NOT require
  reading the object's bytes when a record exists.

### Registered derived attributes

The registry in `reference/property-registry.md` lists attributes; the ones
this specification defines are:

| Attribute | Function | Value |
| --- | --- | --- |
| `hash.sha256` | SHA-256 of plaintext | 32 bytes |
| `hash.sha512` | SHA-512 of plaintext | 64 bytes |
| `hash.git-blob-sha1` | SHA-1 of `blob <len>\0` + plaintext | 20 bytes |
| `hash.git-blob-sha256` | SHA-256 of `blob <len>\0` + plaintext | 32 bytes |
| `class.magic` | content classifier | one of `elf`, `shebang`, `ar`, `zstd`, `gzip`, `tar`, `text`, `other` |
| `class.elf` | ELF header parse | map: class, machine, type, interpreter, needed libraries |
| `class.shebang` | first line parse | interpreter path and argument |

### Registered adapter and writer-supplied attributes

Attributes that a surface, adapter, or writer supplies rather than derives
from content are registered here so that their names are stable across
files. They are validated by the surface schema that requires them
([`30-surface-protocols.md`](30-surface-protocols.md)), not by
recomputation.

| Namespace | Attributes | Supplied by |
| --- | --- | --- |
| `nar.` | `hash_sha256`, `size`, `references`, `deriver`, `signatures`, `ca`, `file_hash`, `file_size`, `compression` | NAR adapter and `nix-cache` surface |
| `nix-cache-info` root attributes | `store_dir`, `priority`, `want_mass_query` | `nix-cache` surface |
| `reapi.` | `size_bytes`, `output_digests` | `reapi` surface |
| `gha.` | `key`, `version`, `scope`, `size`, `created_at` | `gha-cache` surface |
| `oci.` | `media_type`, `subject`, `annotations` | `oci` surface |
| `tag.` | any name | ruleset `tag` actions ([`31-routing-rulesets.md`](31-routing-rulesets.md)) |
| (bare) | `uid`, `gid` | live-filesystem adapters ([`06-tree-format.md`](06-tree-format.md) TREE-9) |
| (bare) | `zstd-dictionary` | dictionary identity ([`05-chunking.md`](05-chunking.md)) |

- **[DRV-6]** `hash.*` attributes MUST be computed over the full plaintext
  of the object as reassembled from its chunks in manifest order. The
  primary content hash of the object is not a derived attribute; it is part
  of the manifest ([`04-content-model.md`](04-content-model.md)).
- **[DRV-7]** The `hash.git-blob-*` attributes are OPTIONAL and enabled by
  listing them in the root's `hashes` property. They exist so that a git
  surface ([`30-surface-protocols.md`](30-surface-protocols.md)) can serve a
  view without hashing at read time.
- **[DRV-8]** `class.magic` MUST examine at most the first 64 KiB of the
  object and MUST be deterministic for a given classifier version. A
  classifier version change MUST be a new function version and MUST NOT
  overwrite records of the old version.

## Producing derived attributes

- **[DRV-9]** A writer committing an entry under a root whose effective
  requirement properties (`hashes`, `classify`) demand an attribute MUST
  either supply a side-table record or an inline attribute for that entry
  ([`08-properties.md`](08-properties.md) PROP-21). A writer MAY skip
  computation when a record already exists in the side table.
- **[DRV-10]** A gateway that admits content from an untrusted writer MUST
  either recompute required derived attributes itself or mark the supplied
  records as untrusted provenance, so that a trust selector can exclude
  them ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)).
- **[DRV-11]** For entries that exist before a requirement property is set,
  a backfill tree job ([`32-tree-jobs.md`](32-tree-jobs.md)) MUST iterate
  the root with the filter `missing(attribute)`, skip objects that already
  have a side-table record, compute the missing records, and checkpoint as
  commits. Completeness ([`08-properties.md`](08-properties.md)) MUST reach
  100% when the job completes with no concurrent commits that omit the
  attribute, which PROP-21 forbids.

## Derivations

- **[DRV-21]** A derivation MUST be identified by the hash of its recipe
  and MUST be memoized, when memoized at all, as a meta object in the
  `terrane-memo-v1` identity domain keyed by that hash and holding the
  resulting root hash. Index trees, realization roots, and materialized
  composites MUST all use this one memo form; an implementation MUST NOT
  keep a second memoization mechanism for any of them.
  *Gate:* `gate:derivation-memo`.
- **[DRV-22]** Every derivation MUST be verifiable by re-evaluating its
  recipe and comparing root hashes, and rebuildable by the same evaluation.
  A derivation whose stored root disagrees with re-evaluation MUST be
  reported and MUST NOT be served until rebuilt. DRV-16 is the index-tree
  instance of this rule; RULE-21 is the realization-root instance.
- **[DRV-23]** A derivation MAY be published under a ref in `refs/derived/`
  ([`09-refs-and-commits.md`](09-refs-and-commits.md) REF-3) so that other
  hosts can find it by name; the ref is a convenience and its loss MUST NOT
  affect correctness.

### Index trees

- **[DRV-12]** For each attribute named in a root's effective `index`
  property the implementation MUST maintain an **index tree**: a tree in the
  same encoding as [`06-tree-format.md`](06-tree-format.md) whose keys are
  the canonical byte encoding of the attribute value followed by the object
  hash, and whose entries are index entries carrying the object hash and,
  when the property requests it, the referencing paths. *Gate:*
  `gate:index-tree-maintenance`.
- **[DRV-13]** An index tree MUST be referenced from the root's property map
  by attribute name and MUST carry a recipe `index(root hash, attribute)`.
  Its root hash is therefore verifiable by rebuilding from the root.
- **[DRV-14]** A writer MUST update each index tree of a root in the same
  commit that changes the root, applying only the changes in
  `diff(old root, new root)`. The cost MUST be O(delta × log n).
- **[DRV-15]** A `filter` or lookup by attribute value MUST use the index
  tree when one exists and MUST fall back to a full walk otherwise,
  reporting which it did.
- **[DRV-16]** An implementation MUST provide `verify_index(root, attribute)`
  that recomputes the index tree from the root and compares root hashes, and
  `rebuild_index` that replaces a divergent index. A divergent index MUST be
  reported and MUST NOT be served for lookups until rebuilt.
- **[DRV-17]** Index trees are derived data: they MUST NOT be a source of
  truth for any decision that the root itself can answer, and their loss
  MUST be recoverable by rebuild.

#### Lookup by secondary hash

The motivating index is lookup of an object by a hash other than its primary
content hash: a client that knows only the SHA-256 of a file asks the store
for it.

- **[DRV-18]** A store whose roots list `hash.sha256` in both `hashes` and
  `index` MUST answer `lookup(root, hash.sha256, value)` with the set of
  object hashes whose attribute equals `value`, in O(log n) plus the size of
  the result. The answer MUST be filtered by the reader's authority and the
  root's trust selector before it is returned.

### Memos

- **[DRV-19]** A derivation memo (DRV-21) MUST be garbage-collected with the
  root it names and MUST be verifiable by re-evaluating the recipe
  (DRV-22).
- **[DRV-20]** Memos are advisory. An implementation MUST produce identical
  results with memoization disabled.

## Interactions

- [`04-content-model.md`](04-content-model.md) defines the `terrane-attr-v1`
  and `terrane-memo-v1` identity domains.
- [`06-tree-format.md`](06-tree-format.md) defines inline attributes and the
  `index` entry type used by index trees.
- [`07-tree-algebra.md`](07-tree-algebra.md) consults classifications in
  `filter` and `map` and memoizes composites.
- [`08-properties.md`](08-properties.md) defines the `hashes`, `classify`,
  and `index` requirement properties and completeness.
- [`12-pack-format.md`](12-pack-format.md) stores side-table records in
  meta packs.
- [`17-garbage-collection.md`](17-garbage-collection.md) collects records,
  index trees, and memos with the objects and roots they derive from.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md) governs trust
  in records produced by untrusted writers.
- [`30-surface-protocols.md`](30-surface-protocols.md) relies on
  `hash.sha256` indexes for content-addressable protocols and on
  `hash.git-blob-*` for the git surface.
- [`31-routing-rulesets.md`](31-routing-rulesets.md) defines the
  `content_magic` matcher that reads `class.magic`.
- [`32-tree-jobs.md`](32-tree-jobs.md) defines backfill and reindex jobs.

## Informative: why per object, not per entry

A build cache references the same shared library from thousands of package
closures, and a branch model multiplies those references by the number of
live views. Keying derived attributes by entry would make a new hash
algorithm cost a pass over every entry of every view. Keying by object hash
makes it cost one pass over distinct objects, once, forever, and makes a
freshly forked view complete without doing anything. This mirrors how a
version-control system stores a blob once regardless of how many trees name
it, and it is what makes adding a capability to an existing store a
background job rather than a migration.
