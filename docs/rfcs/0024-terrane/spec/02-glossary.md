# 02 — Glossary

Precise definitions for the vocabulary used across the specification. The
defining file is named in parentheses. Terms are grouped by the layer that
owns them.

## The five nouns

- **Chunk** — a content-defined slice of bytes, identified by the hash of its
  plaintext, stored compressed. The unit of deduplication, transfer, and
  verification. (04, 05)
- **Object** — the content of one file: an ordered list of chunks with total
  size and content hashes. Identified by the hash of its manifest. (04)
- **Manifest** — the encoded form of an object. Files small enough to fit in
  one chunk need no manifest; their entry names the chunk directly. (04, 06)
- **Tree** — a persistent, history-independent Merkle map from path to entry,
  stored as prolly-tree nodes. A tree is identified by its root node hash.
  (06, 07)
- **Node** — one encoded prolly-tree node, leaf or internal. (06)
- **Entry** — one key in a tree: a file, directory, symlink, hard-link
  identity, or a `tree` reference to another root, with metadata, attributes,
  and provenance. (06)
- **Commit** — an immutable record binding a tree root to zero or more parent
  commits, provenance, a message, and its profile pair. (09)
- **Identity profile** — a digest algorithm, its output length, and its
  registered domain strings; every identity in a store belongs to exactly
  one. (04)
- **Chunk profile** — a named set of content-defined chunking parameters
  and seed; fixed for every chunk cut with it. (05)
- **Profile pair** — the identity profile and chunk profile a commit
  records as in effect. (09)
- **Trust preset** — a named trust selector such as `any`,
  `signed-baseline`, `strict`, or `attested`. (23)
- **Ref** — a name for a commit. The only mutable state in a store; changed
  only by conditional write. (09)

## Namespace vocabulary

- **Root** — a tree root that is the target of a `tree` entry or a ref. Roots
  are the unit of properties, authority, storage placement, and ownership.
  (06, 08)
- **`tree` entry** — an entry whose target is another root, grafting that
  root's namespace beneath the entry's path. (06, 07)
- **Whiteout entry** — an entry that hides its key in every lower layer of an
  overlay. Meaningful only in layered or upper trees. (06, 07)
- **Conflict entry** — the value of a key that a merge could not resolve: an
  ordered list of candidate entries plus the merge base. Never a failed
  merge; resolved later by policy or by a resolver. (06, 07)
- **Index entry** — an entry in an index tree pointing at the objects that
  carry an attribute value. (06, 10)
- **Property** — a named, typed value on a root that inherits to descendants
  unless overridden. Storage class, domain, trust, redundancy, retention,
  hashing requirements, and access control are properties. (08)
- **Completeness** — for a property that requires derived attributes, the
  fraction of entries under a root that satisfy it. (08, 10)
- **Attribute** — a named value on an entry. Some are supplied by the writer,
  some derived from content and keyed by object hash. (06, 10)
- **Index tree** — the derivation `index(root, attribute)`: a tree keyed by
  an attribute value, maintained as a materialized view of a root. (10)
- **Recipe** — the canonical encoding of a tree-algebra operation and its
  input roots. Its hash identifies the result. (07)
- **Derivation** — a root computed by evaluating a recipe, memoized by the
  recipe hash and verifiable by re-evaluation. Index trees, realization
  roots, and materialized composites are its named kinds. (10)
- **Branch** — a ref under `refs/heads/` that advances by commit. (09)
- **Tag** — a ref under `refs/tags/` that is written once and never changed.
  A **snapshot** is a tag. (09)
- **Reflog** — the ordered log of commits a ref has pointed at, stored under
  `logs/refs/heads/`. (09)
- **Job ref** — a ref under `refs/jobs/` holding a tree job's checkpoints.
  (09, 32)
- **Conflict ref** — a ref under `refs/conflicts/` holding an unresolved
  multi-writer merge that advances only by resolution. (09, 20)
- **Derived ref** — a ref under `refs/derived/` naming a derivation worth
  sharing by name, such as a ruleset's realization root. (09, 10, 31)
- **Fork** — creating a branch whose first commit is another branch's
  current commit. (07, 09)
- **Fold** — merging a branch into the branch it was forked from and retiring
  the fork. (07, 09)
- **Merge base** — the nearest common ancestor commit of two commits. (07, 09)
- **Conflict value** — an entry whose merge result holds more than one
  candidate, resolved by policy or left for a later resolver. (07)

## Views and surfaces

- **View** — a ref or a fixed commit, optionally narrowed to a subtree,
  together with the policy that applies when it is read: trust selectors,
  rulesets, and realization hints. (26)
- **Surface** — a way of exposing a view: a kernel interface or a protocol.
  (26)
- **Exposure** — one `view × surface × endpoint` triple in a running instance.
  (26)
- **Endpoint** — where a surface appears: a mount path, socket, URL prefix,
  or device node. (26)
- **Realizer** — a surface whose endpoint is a kernel object. (26, 27, 28, 29)
- **`realize` role** — the process that runs realizer exposures: builds
  tree indexes, requests sealed objects, requests mounts from the broker.
  (03)
- **Upper** — the private writable layer of a writable exposure. (20, 27)
- **Attachment** — an adopting system's word for an exposure into a sandbox.
  Not used in this specification except in this definition.
- **Schema** — the path layout and attribute set a surface requires of a
  view's root. (26)
- **Ruleset** — an ordered, closed-vocabulary list of match-to-action rules
  applied when a view is realized. (31)

## Storage vocabulary

- **Store** — anything implementing the store interface. `ContentStore`
  is put, get, and has over immutable content; `RefStore` is get,
  compare-and-swap, log, and watch over refs; a `Store` is both. (11)
- **ContentStore** — the immutable-content half of the store interface.
  Every backend implements it. (11)
- **RefStore** — the ref half of the store interface. Implementing it is
  what makes a store an authority. (11)
- **Backend** — a store that owns bytes: `bucket`, `disk`, `shared-dir`,
  `blockdev`, `remote`. (11)
- **Combinator** — a store built from other stores: `routed`, `guard`,
  `replicated`, `striped`. (11, 15)
- **Store expression** — the configuration tree of backends and combinators
  an instance runs. (11)
- **Tier** — one store in a `routed` list. The **authority** is the tier
  that implements `RefStore`; caches implement only `ContentStore`. (11, 19)
- **Pack** — an immutable, self-describing container of chunks or meta objects
  with a trailing index. (12)
- **Meta pack** — a pack holding tree nodes, manifests, commits, and bundles
  rather than data chunks. (12)
- **Index** — a mapping from content hash to pack and offset. Per-pack indexes
  are written with the pack; merged indexes are compacted periodically. (12)
- **Filter** — a compact approximate-membership structure over an index used
  to avoid negotiation round trips. (12, 21)
- **Bundle** — a meta object holding every node of a tree a reader does not
  yet have, shipped ahead of a mount. (12, 18)
- **Sealed object** — a fully assembled file in a host tier, immutable and
  verified, eligible for passthrough. (14)
- **Object directory** — the host tier's flat directory of sealed objects
  keyed by object hash. (14)
- **Pin** — a host-tier promise not to evict content while a consumer needs
  it. (14)
- **Grace window** — the minimum age an unreferenced object must reach before
  garbage collection may remove it. (17)
- **Tombstone** — the marker that removes a pack from service before its
  bytes are deleted. (17)
- **Epoch** — a monotonically increasing number that fences writers: a
  ref's current writer, or the collector holding the GC lease. (09, 17, 20)
- **Generation** — the number of a merged-index publication; readers fetch
  index and filter deltas by generation. (12, 13, 21)
- **Cycle** — one run of the garbage collector; tombstones, root-set
  snapshots, and mark checkpoints are keyed by cycle. (13, 17)

## Distribution vocabulary

- **Hop** — one edge in the tier graph traversed by a request. (19)
- **Locality** — the `{region, zone, host}` label on a store. (19)
- **Cost vector** — measured latency, bandwidth, price, and health for an
  edge. (19)
- **Home** — the region whose authority owns a ref. (19, 20)
- **Residency** — which packs a tier currently holds, advertised as a filter.
  (19)
- **Warming** — fetching content into a tier ahead of demand. (19)
- **Negotiation** — determining which content a receiver lacks before sending
  it. (18, 21)
- **Presigned read** — a time-limited URL minted by a gateway that lets a
  client read bytes directly from a bucket. (18, 22)

## Security vocabulary

- **Principal** — a human, workload, or service identity. (22)
- **Capability token** — a signed, offline-attenuable token carrying grants.
  (22)
- **Grant** — `(pattern, verb)`: authority over refs or roots matching the
  pattern. Verbs are `read`, `fork`, `commit`, `tag`, `admin`. (22)
- **Attenuation** — deriving a narrower token from a token without contacting
  an issuer. (22)
- **Provenance** — who committed an entry, under what token, from what
  process, recorded on the commit and inherited by entries. (23)
- **Trust selector** — a predicate over provenance applied when reading. (23)
- **Disclosure domain** — the boundary within which bytes may be shared and
  deduplicated. (24)

## Operations vocabulary

- **Tree job** — a program that iterates a tree by shards, checkpoints as
  commits, and optionally follows a branch incrementally. (32)
- **Shard** — a key range of a tree of roughly equal weight to its siblings.
  (32)
- **Backfill** — a tree job that brings old entries up to a new property.
  (32, 33)
- **Scrub** — a tree job that re-verifies stored content. (15, 32)
- **Resilver** — restoring redundancy after a store in a redundant set is
  lost. (15)
- **Compaction** — rewriting under-utilized packs and merging indexes. (17)
