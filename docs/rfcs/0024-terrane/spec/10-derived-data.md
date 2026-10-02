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
  attribute for the same object and function version MUST produce identical
  values and function metadata. Their records retain each producer's
  provenance and therefore need not have identical bytes or identities.
  A record claiming a producer for a side-only value MUST include key 6,
  a detached Ed25519 signature made by that verified producer commit's
  token terminal key. Its preimage is the ASCII bytes
  `terrane-attr-signature-v1`, one zero byte, and the canonical AttrRecord
  encoded with key 6 absent. This binds keys 1 through 5 without creating
  a cycle with the already sealed producer commit. An
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
- **[DRV-11] (withdrawn)** For entries that exist before a requirement
  property is set,
  a backfill tree job ([`32-tree-jobs.md`](32-tree-jobs.md)) MUST iterate
  the root with the filter `missing(attribute)`, skip objects that already
  have a side-table record, compute the missing records, and checkpoint as
  commits. Completeness ([`08-properties.md`](08-properties.md)) MUST reach
  100% when the job completes with no concurrent commits that omit the
  attribute, which PROP-21 forbids.
  Replaced by DRV-28 under D-101: an existing side record avoids computation
  but does not fill a missing inline index input.

- **[DRV-28]** For entries that exist before a requirement property is set,
  a backfill tree job MUST visit entries missing the required attribute or
  an applicable inline index input under DRV-27, and checkpoint changes as
  commits. It MUST skip computation when a checked existing side record
  supplies the required function/version and value, but MUST still
  materialize a missing inline index input from that record. Copying its
  checked value MUST NOT read content merely to recompute it. Inline and
  selected side values MUST agree under DRV-4, and producer attribution
  MUST remain independently verified. With no concurrent writes omitting
  applicable required attributes, successful backfill MUST reach 100%
  completeness. Unavailable or invalid evidence MUST leave an explicit gap,
  not count as completed work. PROP-25's initial property installation
  MUST still perform no content read. *Gate:* `gate:derived-attr-record`,
  `gate:index-tree-maintenance`.

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
  when the property requests it, the referencing paths. These are opaque
  byte keys, not filesystem paths. The combined key MUST fit TREE-6's
  4 096-byte limit; a commit whose indexed value cannot fit MUST be rejected
  before publication. *Gate:*
  `gate:index-tree-maintenance`.
- **[DRV-13] (withdrawn)** An index tree MUST be referenced from the root's
  property map
  by attribute name and MUST carry a recipe `index(root hash, attribute)`.
  Its root hash is therefore verifiable by rebuilding from the root.
  Replaced by DRV-25 and DRV-26 under D-101: the association is detached
  so that index bytes do not depend on their own containing root's digest.
- **[DRV-14] (withdrawn)** A writer MUST update each index tree of a root in
  the same commit that changes the root, applying only the changes in
  `diff(old root, new root)`. The cost MUST be O(delta × log n).
  Replaced by DRV-29 under D-103: canonical boundary resynchronization and
  expanded changed-graft data cannot be hidden in a descriptor-only delta.
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

#### Owner binding and executable recipe

- **[DRV-25]** For each required attribute, an owning root MUST bind its
  index's Node identity by attribute name in `index-roots` (PROP-29), or
  report the missing binding as incomplete under DRV-27. The binding MUST
  be validated against the registered recipe's independently rebuilt
  result before the index is accepted as verified. Index nodes MUST NOT
  encode a back-reference to the owner, recipe or memo. A recipe or memo
  association MUST be detached from the owner and index bytes. An
  implementation MUST NOT substitute optional memos or `refs/derived/`
  for the owner binding.
  Rebuilding a divergent binding MUST produce a corrected owner in a new
  commit; it MUST NOT mutate an immutable root. DRV-29's same-commit
  incremental maintenance remains required. *Gate:*
  `gate:index-tree-maintenance`.
- **[DRV-26]** The registered `terrane-index/v1` evaluation profile MUST
  accept exactly the `index-evaluation-recipe` CDDL: operation `index`,
  one completed owner-root operand and arguments `attribute` and `profile`.
  The attribute MUST be registered and the profile MUST be
  `terrane-index/v1`. Evaluation MUST derive DRV-12's value-plus-object
  keys from canonical inline values in the owner's regular-file entries,
  including entries reached through namespace grafts, without incorporating
  `index-roots` or other structural bindings into the indexed data. Each
  resulting row MUST carry exactly the object named in its key. The
  completed owner MUST bind that result before a verified index is served.
  Memoization, when used, MUST use the unchanged DRV-21 memo form and MUST
  NOT affect the result. Generic retained `index` recipes MUST preserve
  their existing encoding and MUST NOT become executable solely by having
  the `index` operation string. *Gate:* `gate:derivation-memo`,
  `gate:index-tree-maintenance`.
- **[DRV-27]** For each effective `index` attribute applicable to an added
  or modified regular-file entry, a writer MUST supply its canonical value
  inline, even when a side record already exists. This does not replace
  the required content/attribute-producer verification. A missing applicable
  inline value, missing owner binding, unavailable evidence or unsupported
  occurrence coverage MUST be reported as incomplete; absence MUST NOT be
  taken as proof that a value differs from the lookup argument. Conditional
  `class.elf` and `class.shebang` applicability MUST follow PROP-19 and the
  registered classifier rules. Proven nonapplicability MAY count as covered
  only with independently checked immutable applicability evidence; an
  implementation MUST NOT invent a sentinel value. Unless relevant gaps
  are closed or independently excluded by the reader's current policy,
  lookup MUST return a typed incomplete result, or an explicitly partial
  and incomplete response, rather than a definitive complete or empty set.
  Existing untouched entries MAY remain incomplete under PROP-22/25.
  Reporting incompleteness MUST NOT permit discarding an existing valid
  required binding or replace DRV-29's same-commit maintenance. Missing
  binding allowances apply to initial requirement installation, preserved
  pre-existing gaps or unavailable read evidence, not deliberate omission
  of an otherwise required maintained index.
  The indexed rows MUST exactly represent all present canonical inline
  values for the named attribute, independent of current policy, producer
  evidence availability or classifier applicability. Applicability determines
  missing-value coverage and admission, not omission of a present row.
  Verifying those rows alone MUST NOT establish complete coverage. Reporting
  coverage and gaps MUST obey current authority. *Gate:*
  `gate:index-tree-maintenance`, `gate:property-required-attrs`.

Construction is acyclic: build the index `I` from candidate entries, bind
`I` to complete the owner `R`, then form the recipe `Q` and optional memo.
The recipe hash is the memo lookup key; it is distinct from the immutable
identity of the encoded memo itself.

```text
Q = {1: "index", 2: [R],
     3: {"attribute": A, "profile": "terrane-index/v1"}}
q = BLAKE3("terrane-memo-v1\0" || canonical-CBOR(Q))
M = {1: q, 2: I}                     # optional existing memo form
entries -> I -> R -> Q/q -> optional M
```

The recipe's data inputs are immutable beneath `R`. Mutable side-table
selection is not an implicit extra recipe input. Side records remain useful
for computation reuse and producer evidence; indexed values are materialized
inline so that re-evaluation does not select a different function or value
from a changed catalog. Lookup still checks the actual current occurrence,
its content and value, producer evidence, authority and trust under DRV-24.

#### Lookup by secondary hash

The motivating index is lookup of an object by a hash other than its primary
content hash: a client that knows only the SHA-256 of a file asks the store
for it.

- **[DRV-18] (withdrawn)** A store whose roots list `sha256` in `hashes` and
  `hash.sha256` in `index` MUST answer `lookup(root, hash.sha256, value)`
  with the set of object hashes whose attribute equals `value`, in O(log n)
  plus the size of the result. The answer MUST be filtered by the reader's
  authority and the root's trust selector before it is returned.
  Replaced by DRV-24 under D-100: the number of returned objects does not
  bound the work of rejecting independently governed occurrences.

- **[DRV-24]** A store whose roots list `sha256` in `hashes` and
  `hash.sha256` in `index` MUST, when relevant coverage is complete under
  DRV-27, answer `lookup(root, hash.sha256, value)`
  with exactly the deduplicated set of matching object hashes having a
  currently authorized and trusted occurrence in that view. With a
  validated index of size `n`, discovery of the equality-range candidate
  rows MUST cost O(log n + C), where `C` is the number of candidate rows
  examined before authority and trust filtering. Implementations MUST
  account separately for the `P` candidate path occurrences examined and
  the additional `W` work of occurrence-tree traversal, path resolution,
  current-policy checks and provenance verification. Total lookup work
  MUST be reported in these terms, O(log n + C + P + W), rather than
  claiming a bound in the size of the filtered answer alone. Coverage gaps
  MUST instead yield DRV-27's incomplete response. Index validation or
  rebuilding work MUST be reported separately when needed.
  Before returning an object, the implementation MUST verify the actual
  occurrence's content identity and attribute value, the reader's current
  authority, independently required attribute-producer evidence, and the
  root's trust selector. Unfiltered candidates MUST NOT be exposed as
  answers, and a full-root walk MUST NOT substitute for indexed candidate
  discovery when the index exists. DRV-16 governs divergent indexes.
  *Gate:* `gate:index-tree-maintenance`.

For example, one object can occur under many independently governed grafts.
If every occurrence denies the reader, the answer is empty but each relevant
policy may still need examination. An ancestor denial can prune some views;
it does not establish a general filtered-output bound for all views. The
index narrows candidate discovery; it does not eliminate current policy or
producer verification.

#### Incremental maintenance and work accounting

The cost below applies separately to each maintained index and its registered
occurrence and missing-value structures. Work over multiple owning roots or
indexed attributes is summed. Here `n` is the largest entry cardinality among
the relevant old/new namespace inputs, necessarily descended graft targets and
auxiliary trees. Its independently defined logical changes and work are:

- `delta_input`: changed logical namespace entries and root-property bindings
  after necessary changed-graft descent, including changes to nonparticipating
  entries, or the equivalent logical changes compared in immutable indexed
  summaries when available. Unchanged scanned entries are not input delta.
- `delta_data`: changed participating regular-file occurrence states after
  necessary changed-graft descent, including object identity, canonical inline
  attribute presence/value and occurrence membership. A newly enabled indexed
  population and added or removed graft contents contribute their actual
  indexed occurrences, rather than one opaque descriptor change.
- `delta_route`: changed logical local-route, continuation, gap and structural
  bindings representing those occurrences. Distinct graft occurrences remain
  distinct even when they share a child tree. Node identity changes caused only
  by canonical repartitioning are not logical route changes. Overlap among the
  three logical counters is reported consistently, not inferred from visits.
- `B`: additional physical work caused by canonical boundary divergence and
  resynchronization, at every level of the compared namespace and updated
  index/occurrence/gap trees. Its cost model assigns one unit per item read,
  comparison or frontier check, and one unit per byte encoded or hashed. `B`
  is the sum of these separately reported counters; item-size and key bounds
  remain fixed. Each region is attributed to its invalidated boundary and
  compatible resynchronization point or stream tail; repeated processing is
  charged repeatedly. An unconditional scan is not boundary work merely because
  it occurred.

- **[DRV-29]** A writer MUST update each maintained required index and its
  registered occurrence and missing-value structures in the same commit that
  changes their owning root. Incremental maintenance MUST derive updates from
  changed entries, root properties and graft occurrences in the old/new
  immutable inputs. It MUST descend changed graft targets when required to
  identify indexed-data changes, or compare equivalent immutable indexed
  summaries; a single descriptor change MUST NOT stand for multiple changed
  indexed occurrences in the reported delta.
  Maintenance MUST start in affected ranges, skip equal immutable subtrees,
  reuse unchanged subtrees whose boundaries remain canonical, and rechunk only
  affected boundary regions until resynchronization or the affected stream's
  end. Overlapping affected regions MUST be processed as a batch rather than
  restarting their shared suffix for each point edit. It MUST NOT substitute an
  unconditional full-root walk or full-index rebuild for incremental
  maintenance of a valid existing index. Canonical output MUST continue to
  satisfy TREE-22 to TREE-24.
  Maintenance MUST report `delta_input`, `delta_data`, `delta_route` and `B`
  as defined above. Local work MUST be
  O((1 + delta_input + delta_data + delta_route) × log(max(2, n)) + B).
  Expected work under the specified content-hash boundary distribution is
  O((1 + delta_input + delta_data + delta_route) × log(max(2, n)));
  adversarial canonical boundary shifts MAY require linear resynchronization
  work. Additional boundary work MUST be measured and MUST NOT be hidden by
  counting unchanged scanned entries as logical delta. Initial construction,
  independent validation and explicit verification/rebuild costs MUST be
  reported separately and MUST NOT establish an incremental-maintenance cost
  claim.
  DRV-16/17 verification, divergent-index refusal and rebuild, DRV-24 current
  occurrence/producer/authority/trust checks, and DRV-27 completeness remain
  required. Reporting gaps MUST NOT permit dropping an otherwise maintained
  valid required index. *Gate:* `gate:index-tree-maintenance`.

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
