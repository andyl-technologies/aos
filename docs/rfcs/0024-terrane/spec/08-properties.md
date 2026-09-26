# 08 — Properties

This file owns properties: named, typed values on roots that inherit to
descendant roots and govern how the entries beneath them are stored, trusted,
realized, protected, and completed. Properties are the configuration model of
a store. There is no configuration beside the tree: a root's effective
properties say where its bytes go, who may write it, what its entries must
carry, and how it is shown. The registered property names, types, and
defaults are in `reference/property-registry.md`.

## Model

A [root](02-glossary.md#namespace-vocabulary) is a tree root reached from a
ref or from a `tree` entry. Each root MAY carry a property map. A property is
a name from the registry, a value of the registered type, and an optional
`inherit` flag (default true). The **effective** value of a property at a
root is its own value if set, otherwise the effective value at the nearest
ancestor root that sets it, otherwise the registry default.

Properties are part of the root's identity: the property map is encoded in
the root node ([`06-tree-format.md`](06-tree-format.md)), so changing a
property is a commit and appears in `diff`. This gives every configuration
change provenance, a diff, and a rollback.

An example property tree for a store that serves a public package store, a
private workspace, a tenant-scoped build cache, and a signed action cache:

```text
/                domain=public   store=warehouse   chunk=cdc-1m   retain=gc
/nix/store       (inherits)                                       dedup=global
/workspace       domain=private  store=host-local  wipe=zero      retain=lease
/gha             domain=tenant   store=warehouse   retain=7d
/bazel/ac        domain=tenant   trust=signed-build
```

Each line is a root. `/nix/store` inherits everything and adds one value;
`/workspace` overrides four.

## Resolution

- **[PROP-1]** The effective value of property `p` at root `R` MUST be
  computed as: `R`'s own value if present; else the effective value at the
  nearest ancestor root along the graft path that sets `p` with
  `inherit=true`; else the registry default. An ancestor value with
  `inherit=false` MUST NOT propagate. *Gate:* `gate:property-resolution`.
- **[PROP-2]** The graft path used for resolution MUST be the path by which
  the root was reached in the current view. A root reachable by two paths
  MAY therefore have different effective properties in each; an
  implementation MUST NOT cache effective properties by root hash alone.
- **[PROP-3]** A property value MUST be of its registered type. A commit
  that sets a property with a value of the wrong type, or sets an
  unregistered property, MUST be rejected.
- **[PROP-4]** Unknown registered properties (registered in a later minor
  version) MUST be preserved verbatim by an implementation that does not
  understand them and MUST NOT affect its behavior.

## Property classes

Properties are grouped by the layer that consumes them. The registry is
authoritative; this section defines the semantics each class carries.

### Storage

- **[PROP-5]** `store` names the store expression that holds the chunks and
  meta objects of entries beneath the root
  ([`11-store-trait.md`](11-store-trait.md)). A writer MUST place new content
  for an entry in the effective `store` of the entry's nearest root. A reader
  MUST resolve content through that store's tiers and MAY additionally
  consult any store it can reach.
- **[PROP-6]** `chunk` names a chunk profile from
  [`05-chunking.md`](05-chunking.md). Content beneath the root MUST be
  chunked with that profile. Changing `chunk` affects only new content;
  existing content is migrated by a tree job ([`33-migrations.md`](33-migrations.md)).
- **[PROP-7]** `compression` names a codec and optional dictionary class. It
  affects only new content.
- **[PROP-8]** `encryption` names a key reference for at-rest encryption of
  chunks beneath the root, or `none`. This specification reserves the
  property and its semantics for a later minor version; an implementation
  MUST reject a value other than `none`.
- **[PROP-9]** `retain` selects the garbage-collection policy for the root:
  `gc` (reachability from refs, with reflog entries kept for the property's
  duration), `lease` (unreferenced when the lease named on the commit
  expires), `ttl` with a duration (kept for a fixed time from the commit),
  or `forever`. See [`17-garbage-collection.md`](17-garbage-collection.md).
- **[PROP-10]** `domain` names the disclosure domain
  ([`24-disclosure-domains.md`](24-disclosure-domains.md)). `dedup` selects
  the scope of chunk deduplication: `global`, `domain`, or `none`. `dedup`
  MUST NOT be wider than what `domain` permits.
- **[PROP-11]** `redundancy` names a redundancy policy from
  [`15-redundancy.md`](15-redundancy.md); `durability` names the
  acknowledgement level from [`20-consistency.md`](20-consistency.md);
  `replicate` names the cross-region replication mode from
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md).

### Trust

- **[PROP-12]** `trust` names a trust selector
  ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)) applied to
  every entry resolved beneath the root. An entry whose provenance does not
  satisfy the effective selector MUST be invisible to the reader, as if
  absent.
- **[PROP-13]** `merge` names the ordered list of merge policies used to
  resolve conflict values when this root is the target of a merge
  ([`07-tree-algebra.md`](07-tree-algebra.md)).

### Realization hints

- **[PROP-14]** `prefetch`, `reassembly`, `passthrough`, and `wipe` are
  hints consumed by host tiers and realizers
  ([`14-host-tier.md`](14-host-tier.md), [`27-surface-fuse.md`](27-surface-fuse.md)).
  A hint MUST NOT change the namespace or identity of any object, and an
  implementation MAY ignore a hint it does not support, reporting so in
  status ([`34-observability.md`](34-observability.md)).
- **[PROP-15]** `wipe` is the exception to PROP-14's discretion: when
  `wipe` is `zero`, `discard`, or `volatile`, a host tier MUST honor it or MUST
  refuse to admit content beneath the root.

### Authority

- **[PROP-16]** `acl` is an ordered list of `(principal-or-group, verb)`
  grants evaluated by [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md).
  `acl` MUST have `inherit=true` semantics with the additional rule that a
  descendant root MAY narrow but MUST NOT widen the set of principals
  granted `commit` or `admin` unless the committing principal holds `admin`
  on the ancestor.
- **[PROP-17]** `domain`, `store`, and `acl` are **boundary properties**. A
  `flatten` across roots with differing effective boundary properties MUST
  fail ([`07-tree-algebra.md`](07-tree-algebra.md)).

### Requirements

Requirement properties declare attributes that entries beneath the root must
carry. They are the mechanism by which a store gains capabilities (a second
hash algorithm, a secondary index, a classification) without a format change.

- **[PROP-18]** `hashes` is a set of digest algorithms. Every regular-file
  entry beneath the root MUST carry a content-hash attribute for each
  algorithm listed, as defined in [`10-derived-data.md`](10-derived-data.md).
- **[PROP-19]** `classify` is a set of classifier names. Every regular-file
  entry beneath the root MUST carry the classification attribute produced by
  each listed classifier.
- **[PROP-20]** `index` is a set of attribute names. The root MUST maintain
  an index tree for each listed attribute
  ([`10-derived-data.md`](10-derived-data.md)).
- **[PROP-21]** A commit MUST supply every attribute required by the
  effective requirement properties for each entry it **adds or modifies**. A
  commit that omits a required attribute MUST be rejected. *Gate:*
  `gate:property-required-attrs`.
- **[PROP-22]** A commit MUST NOT be rejected because entries it does not
  touch lack a required attribute. Pre-existing gaps are reported as
  incompleteness and closed by backfill.

## Completeness

- **[PROP-23]** For each requirement property `p` in effect at root `R`, an
  implementation MUST be able to report **completeness**: the number of
  entries beneath `R` that satisfy `p` and the number that do not. The
  report MUST be computed from the tree and the derived-data store, not from
  a separately maintained counter, so that it cannot drift.
- **[PROP-24]** Completeness MAY be cached per (root hash, property, graft
  path) and MUST be invalidated when either the root or any ancestor's
  effective requirement properties change.
- **[PROP-25]** Setting a requirement property on a root with existing
  entries MUST succeed immediately, leave completeness below 100%, and
  record in status that a backfill job ([`32-tree-jobs.md`](32-tree-jobs.md))
  is required. It MUST NOT trigger any content read at commit time.

## Cross-domain checks at commit

- **[PROP-26]** At commit, for every entry added or modified, the
  implementation MUST verify that the objects it references are permitted by
  the effective `domain` of the entry's root under the rules of
  [`24-disclosure-domains.md`](24-disclosure-domains.md). A commit that would
  make a wider domain reference content of a narrower domain MUST be
  rejected. *Gate:* `gate:property-domain-reference`.
- **[PROP-27]** At commit, for every `tree` entry added or modified, the
  implementation MUST verify that the target root's own boundary properties
  are compatible with the effective boundary properties at the graft point
  (a private root MAY be grafted under a public parent; a public root MAY be
  grafted anywhere; a root MUST NOT be grafted where the graft would widen
  its effective `domain`).

## Property summary

Every property named anywhere in this specification is listed here with its
class, type, default, and the file that defines its semantics. The registry
in [`reference/property-registry.md`](reference/property-registry.md) copies
this table and adds encoding details; a name absent from both is
unregistered (CONV-3).

| Property | Class | Type | Default | Defined in |
| --- | --- | --- | --- | --- |
| `store` | storage, boundary | store expression name | the instance's authority | 08, 11 |
| `chunk` | storage | chunk profile name | `cdc-1m` | 05, 08 |
| `compression` | storage | codec and optional dictionary class | `zstd` | 05, 08 |
| `encryption` | storage | key reference or `none` | `none` | 08, 24 |
| `retain` | storage | `gc` \| `lease` \| `ttl=<duration>` \| `forever` | `gc` | 08, 17 |
| `domain` | storage, boundary | disclosure domain | `private:<id>` | 08, 24 |
| `dedup` | storage | `global` \| `domain` \| `none` | `domain` | 08, 24 |
| `redundancy` | storage | redundancy policy or `none` | `none` | 15 |
| `degraded` | storage | `allow` \| `refuse` | `refuse` | 15 |
| `durability` | storage | `local` \| `zone` \| `region` \| `regions(k)` | `region` | 20 |
| `replicate` | storage | `async` \| `sync(k)` \| `none` | `async` | 19 |
| `home` | storage | locality (region) | authority's region at first write | 19, 09 |
| `warm` | storage | list of localities | empty | 19 |
| `quota` | storage | bytes a root may hold, and bytes a principal may write ahead of a ref update | unlimited | 14, 22 |
| `compaction_threshold` | storage | utilization ratio | `0.5` | 17 |
| `whole_pack_threshold` | storage | fraction of a pack needed to fetch it whole | `0.5` | 21 |
| `gap_merge_bytes` | storage | bytes | 256 KiB | 21 |
| `span_max_bytes` | storage | bytes | 16 MiB | 21 |
| `trust` | trust | trust selector or profile name | `any` | 23 |
| `baseline` | trust | group name the `signed-baseline` and `strict` profiles refer to | none | 23 |
| `merge` | trust | ordered merge policy list | `[prefer-trusted, keep-conflict]` | 07 |
| `writers` | trust | `one` \| `many` | `one` | 20 |
| `reflog_retain` | trust | duration or count | 90 days | 09 |
| `prefetch` | realization hint | `profile` \| `rules` \| `none` | `profile` | 31, 27 |
| `reassembly` | realization hint | `never` \| `smart` \| `always` | `smart` | 14 |
| `passthrough` | realization hint | `auto` \| `force` \| `off` | `auto` | 27 |
| `wipe` | realization hint (mandatory when set) | `none` \| `zero` \| `discard` \| `volatile` | `zero` for `private`, else `none` | 14, 24 |
| `on-release` | realization hint | `keep` \| `commit` \| `discard` | `keep` | 20 |
| `acl` | authority, boundary | ordered grants | inherited | 22 |
| `hashes` | requirement | set of digest names (`sha256`, `sha512`, `git-blob-sha1`, `git-blob-sha256`) | empty | 10 |
| `classify` | requirement | set of classifier names | empty | 10 |
| `index` | requirement | set of attribute names | empty | 10 |
| `strict-attrs` | requirement | boolean | `false` | 06 |

- **[PROP-28]** The registry MUST contain every property in the table above
  with the same class and type, and an implementation MUST reject a
  property name that is in neither.

## Interactions

- [`06-tree-format.md`](06-tree-format.md) encodes the property map in the
  root node.
- [`07-tree-algebra.md`](07-tree-algebra.md) respects boundary properties in
  `flatten` and reads the `merge` property.
- [`10-derived-data.md`](10-derived-data.md) defines the attributes that
  requirement properties demand and the index trees they maintain.
- [`11-store-trait.md`](11-store-trait.md), [`15-redundancy.md`](15-redundancy.md),
  [`17-garbage-collection.md`](17-garbage-collection.md),
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md), and
  [`20-consistency.md`](20-consistency.md) consume the storage properties.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)
  evaluates `acl`.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md) and
  [`24-disclosure-domains.md`](24-disclosure-domains.md) consume `trust`,
  `domain`, and `dedup`.
- [`32-tree-jobs.md`](32-tree-jobs.md) and [`33-migrations.md`](33-migrations.md)
  close completeness gaps.
- `reference/property-registry.md` is the authoritative list of names,
  types, defaults, and inherit flags.

## Informative: properties as the whole configuration

Placing configuration in the tree rather than beside it means a store has one
source of truth that is versioned, diffable, and signed. The cost is that a
property change is a commit and therefore subject to the same authority and
merge rules as content, which is the intended behavior: a change to who may
write a root is exactly as auditable as a change to what is in it.
