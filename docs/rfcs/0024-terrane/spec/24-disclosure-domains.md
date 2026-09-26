# 24 — Disclosure domains

This file owns the boundary within which bytes may be shared: the `domain`
property on roots, what it permits between principals and between tiers,
how deduplication is scoped by it, what references may cross it, what a
store may reveal about content existence across it, and what erasure and
encryption guarantees attach to it. Authorization decides who may read a
ref; a domain decides whose bytes may ever sit in the same place.

## Model

A [disclosure domain](02-glossary.md#security-vocabulary) is a label on a
[root](02-glossary.md#namespace-vocabulary), inherited like every other
[property](02-glossary.md#namespace-vocabulary), that names the set of
principals who may learn anything about the content beneath that root: its
bytes, its hashes, or the fact that a given hash exists. Content-addressed
storage deduplicates by hash, and a hash lookup is an existence oracle, so
the domain is the unit at which deduplication, caching, and existence
answers are scoped. Two roots in the same domain share bytes freely; two
roots in different domains never share a chunk record, a sealed object, or
a page-cache page, even when their content is identical.

Four domain kinds cover the practical cases. `public` content is shared by
everyone the store serves and deduplicated globally. `tenant` content is
shared within one named tenant. `group` content is shared within one named
group of principals that may span tenants. `private` content is shared with
nobody but its own root: it is not deduplicated against anything else, is
never advertised, and is wiped when unpinned. A root may reference content
in a more open domain than its own, never a more closed one, so that a
private workspace can sit on top of a public store while a public tree can
never leak a private byte.

## The `domain` property

- **[DOM-1]** Every root MUST have an effective `domain` property. Its
  value is one of `public`, `tenant:<name>`, `group:<name>`, or
  `private:<id>`, where `<id>` is unique to the root. On a host with
  several local users, a user's own roots are `private:<principal>` by
  default so that dedup and kernel-object sharing never cross users, a
  boundary that POSIX mode bits alone do not give. A tree with no
  explicit `domain` on any ancestor MUST be treated as `private:<root
  identity>`. *Gate:* `gate:dom-default-private`.
- **[DOM-2]** `domain` inherits to descendant roots. A descendant MAY set
  a more closed domain than its ancestor. A descendant MUST NOT set a more
  open domain; an attempt MUST fail at commit. The ordering from open to
  closed is `public` < `tenant` < `group` < `private`; two `tenant` or two
  `group` domains with different names are incomparable and a descendant
  MUST NOT move between them.
- **[DOM-3]** A commit that changes a root's `domain` toward a more closed
  value MUST be treated as introducing every entry beneath it anew for
  the purposes of deduplication scoping (DOM-8): existing chunk records
  in the old domain are not reused. The content bytes need not be
  re-uploaded if the store can move records without exposing them.
- **[DOM-4]** A commit that would change a root's `domain` toward a more
  open value MUST be rejected. Publishing private content is done by
  committing it into a root that already carries the open domain, under a
  principal authorized to `commit` there, which produces a provenance
  record of the disclosure.

## Cross-domain references

- **[DOM-5]** An entry beneath a root in domain `D` MAY reference an
  object whose chunk records live in a domain `D'` only if `D'` is equal
  to `D` or more open than `D` under the DOM-2 ordering. A `tree` entry
  beneath a root in `D` MAY target a root in `D'` under the same rule.
  *Gate:* `gate:dom-reference-order`.
- **[DOM-6]** The rule in DOM-5 MUST be checked at commit for every entry
  and `tree` entry the commit introduces, and at merge for every entry a
  merge carries into a root from a different-domain source. A violation
  MUST fail the commit; an implementation MUST NOT silently copy content
  into the more open domain to satisfy the reference.
- **[DOM-7]** Because a `public` root may not reference private content,
  a fold of a private branch into a public baseline MUST first admit the
  branch's new content into the public domain (DOM-3 in reverse: new chunk
  records in `public`) under the folding principal's authority, and this
  admission MUST be recorded in the fold commit's provenance
  ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)).

## Deduplication scoping

- **[DOM-8]** Chunk records, object manifests, and tree nodes MUST be
  deduplicated only within one domain. A store MUST key its index by
  `(domain, hash)` for non-public domains, and MAY key `public` content by
  hash alone. Two identical chunks in different domains are two records.
  *Gate:* `gate:dom-dedup-scope`.
- **[DOM-9]** Pack bytes MAY be shared across domains by a store that
  keeps the per-domain records separate, provided that a reader in one
  domain cannot learn from any observable behavior (a `has` answer, a
  presigned range, a latency difference the implementation controls)
  that the bytes were already present for another domain. If an
  implementation cannot make that guarantee, it MUST NOT share pack bytes
  across domains. Pack sharing across `private` domains is NOT permitted
  under any conditions.
- **[DOM-10]** The `has` operation and negotiation
  ([`18-protocol.md`](18-protocol.md), [`21-bandwidth.md`](21-bandwidth.md))
  MUST answer only for the domain named by the requester's token and
  target root. A hash present in another domain MUST be reported as
  absent. A client that uploads content already present in another
  domain therefore uploads it again, and the store MUST accept the upload
  and create the record in the requester's domain.
- **[DOM-11]** Filters advertised for negotiation
  ([`12-pack-format.md`](12-pack-format.md)) MUST be built per domain and
  MUST NOT be served to a requester whose token does not name that domain.
  A `public` filter MAY be served to any authenticated requester.

## Host tiers and sharing

- **[DOM-12]** A host tier ([`14-host-tier.md`](14-host-tier.md)) MUST keep
  one object directory per domain it serves, or an equivalent isolation
  that prevents a sealed object admitted for one domain from being served
  for another. Within a domain, a sealed object MUST be shared by every
  consumer of that domain on the host, including through the kernel page
  cache. *Gate:* `gate:dom-host-isolation`.
- **[DOM-13]** A `shared-dir` tier ([`11-store-trait.md`](11-store-trait.md))
  exposes exactly one domain's object directory. A nested instance that
  serves several domains MUST be given one `shared-dir` per domain and
  MUST route by the effective domain of the root being read.
- **[DOM-14]** Surfaces that share kernel objects across consumers (FUSE
  passthrough backing files, EROFS data-only lower layers, virtiofs DAX
  mappings) MUST share only within one domain. A host MUST refuse to
  realize a view whose roots span domains onto a single shared backing
  directory unless every consumer of that realization is authorized for
  every domain involved.
- **[DOM-15]** A `private` domain's sealed objects MUST be reference
  counted by consumer, MUST NOT be admitted to any shared cache tier, and
  MUST be wiped (DOM-18) when the last consumer releases them.

## Existence oracles and side channels

- **[DOM-16]** For non-public domains, any operation whose outcome depends
  on whether a hash is already present MUST be indistinguishable to a
  requester outside the domain from the outcome for an absent hash. This
  applies to `has`, negotiation, presigned-read minting, ref-independent
  object fetches, and error codes. *Gate:* `gate:dom-existence-oracle`.
- **[DOM-17]** Timing differences between "present in another domain" and
  "absent" that arise from shared pack bytes (DOM-9), shared page cache,
  or shared network paths are a documented residual risk in
  [`25-threat-model.md`](25-threat-model.md). An implementation that
  claims the Security conformance level MUST document which of these
  channels it closes and which it leaves open, and MUST close every
  channel it controls in software (for example, by not short-circuiting a
  lookup on a cross-domain hit).

## Erasure and wipe

- **[DOM-18]** A root MAY set a `wipe` property with a value from
  `{none, zero, discard, volatile}` ([`14-host-tier.md`](14-host-tier.md)).
  `private` domains MUST default to `zero`; other domains default to
  `none`. On eviction or release of content under a root with `wipe` other
  than `none`, a host tier MUST apply the named strategy before the storage
  is reused: `none` unlinks the file without overwriting it, `zero`
  overwrites it before removal, `discard` issues a discard to the device
  before removal, and `volatile` requires that the content was never
  written to persistent storage (memory-backed tier only). *Gate:*
  `gate:dom-wipe`.
- **[DOM-19]** Content under a `volatile` wipe policy MUST NOT be admitted
  to a persistent tier at any point, including packs written by a
  committing writer on that host; commits of such content go directly to
  the authority store over the network from memory.
- **[DOM-20]** A bucket backend MUST support a per-domain deletion
  operation that removes every pack and index record for a `private` or
  `tenant` domain, so that a tenant's departure can be honored by
  deletion rather than by waiting for garbage collection. This operation
  requires `admin` on the domain's roots and MUST be recorded.

## Encryption at rest

Encryption is a property slot; this version specifies the slot and the
invariants, not the cryptographic protocol.

- **[DOM-21]** A root MAY set an `encryption` property naming a registered
  scheme and a key identifier. When set, every chunk, manifest, and tree
  node introduced beneath that root MUST be stored encrypted under a key
  derived from the named key and MUST NOT be deduplicated against
  unencrypted records or records under a different key. The scheme
  registry is in `reference/property-registry.md` §encryption and is empty
  in this version.
- **[DOM-22]** Content identity ([`04-content-model.md`](04-content-model.md))
  is the hash of plaintext. An implementation MUST NOT expose plaintext
  hashes of encrypted content to any principal not authorized for the
  root, which means index entries for encrypted content MUST themselves be
  keyed by a keyed hash rather than the plaintext hash.
- **[DOM-23]** Key material MUST be held by the store process that
  serves the domain and by no surface, sandbox, or presigned-read holder.
  A presigned read of encrypted content yields ciphertext.

## Interactions

- [`08-properties.md`](08-properties.md) defines `domain`, `wipe`, and
  `encryption` as registered properties and their inheritance.
- [`11-store-trait.md`](11-store-trait.md) defines `shared-dir` and the
  routing DOM-13 requires.
- [`12-pack-format.md`](12-pack-format.md) defines indexes and filters;
  DOM-8 and DOM-11 constrain their keys and distribution.
- [`14-host-tier.md`](14-host-tier.md) implements DOM-12, DOM-15, and
  DOM-18.
- [`18-protocol.md`](18-protocol.md) and [`21-bandwidth.md`](21-bandwidth.md)
  implement DOM-10 and DOM-16 for `has` and negotiation.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)
  provides the `domain` caveat and the token claims that name a tenant or
  group.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md) records the
  disclosure a fold performs (DOM-7).
- [`25-threat-model.md`](25-threat-model.md) analyzes the residual channels
  DOM-17 names.
- [`27-surface-fuse.md`](27-surface-fuse.md),
  [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md), and
  [`29-surface-vm.md`](29-surface-vm.md) implement DOM-14.

## Informative: a typical layout

```text
/                     domain=public          shared store paths, deduplicated by everyone
/cache/<tenant>       domain=tenant:<t>      build caches shared within one tenant
/review/<group>       domain=group:<g>       content shared by a cross-tenant review group
/workspace/<sandbox>  domain=private:<id>    scratch, wipe=zero, never advertised
```

A sandbox's view grafts all four beneath one namespace. Its reads of
`/` come from the host's public object directory and share page cache with
every other sandbox; its reads of `/workspace` come from a per-sandbox
directory that is zeroed when the sandbox ends. A commit that tried to
symlink or `tree`-reference `/workspace` content from beneath `/` would be
rejected at commit by DOM-5.
