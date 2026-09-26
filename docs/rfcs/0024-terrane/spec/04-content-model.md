# 04 — Content model

This file defines the five kinds of things a Terrane store holds, how each is
identified, and the rules that make identities stable across
implementations, versions, and digest algorithms. Every later format cites
the identity rules here rather than restating them.

## Overview

Four of the five nouns are immutable and content-addressed; the fifth, the
ref, names one of them and is the only mutable state
([`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md) INV-1,
INV-2).

| Noun | Is | Identified by | Mutable |
| --- | --- | --- | --- |
| Chunk | a content-defined slice of file bytes | hash of the plaintext slice | no |
| Object | the content of one file: an ordered chunk list, size, content hashes | hash of the encoded manifest | no |
| Tree | a path-keyed Merkle map, stored as prolly-tree nodes | hash of the encoded root node | no |
| Commit | a tree root, parents, provenance, message, profile | hash of the encoded commit | no |
| Ref | a name for a commit | its name | yes, by conditional write |

Packs, indexes, bundles, and filters are containers and caches over these
five and are identified the same way, but they are never part of a
namespace's identity and a reader of the repository layer never sees them
([`12-pack-format.md`](12-pack-format.md)).

## Identity

Every immutable is identified by a digest over a **type domain** followed by
the immutable's encoded bytes. The domain string binds the digest to the kind
of thing it identifies, so a chunk whose bytes happen to equal an encoded
tree node has a different identity from that node.

```text
identity(kind, bytes) = H( domain(kind) || 0x00 || bytes )
```

where `H` is the profile's digest algorithm and `domain(kind)` is the
registered ASCII domain string for the kind, without a terminator other than
the single zero byte shown.

- **[OBJ-1]** The digest algorithm of the initial profile, `terrane-v1`, is
  BLAKE3 with a 32-byte output. Every identity in a `terrane-v1` store is 32
  bytes. *Gate:* `gate:identity-idempotence`.
- **[OBJ-2]** The domain strings of `terrane-v1` are:

  | Kind | Domain |
  | --- | --- |
  | chunk | `terrane-chunk-v1` |
  | manifest (object) | `terrane-manifest-v1` |
  | tree node | `terrane-node-v1` |
  | commit | `terrane-commit-v1` |
  | bundle | `terrane-bundle-v1` |
  | pack | `terrane-pack-v1` |
  | index | `terrane-index-v1` |
  | filter | `terrane-filter-v1` |
  | derived attribute record | `terrane-attr-v1` |
  | policy object (ruleset, token schema) | `terrane-policy-v1` |
  | recipe memo | `terrane-memo-v1` |

  An implementation MUST NOT compute an identity with an unregistered
  domain. New domains are added to
  [`reference/bucket-key-registry.md`](reference/bucket-key-registry.md)
  under the identity-domain table before use (CONV-3).
- **[OBJ-3]** A chunk's identity is computed over its plaintext, never over
  its compressed form. Compression is a storage detail of packs
  ([`05-chunking.md`](05-chunking.md), [`12-pack-format.md`](12-pack-format.md)).
- **[OBJ-4]** The identity of every kind other than chunk is computed over
  its canonical encoding as defined in
  [`reference/terrane-v1.cddl`](reference/terrane-v1.cddl). Two encodings
  that decode to the same value but differ in bytes are two different
  immutables, so canonical encoding is mandatory
  ([`06-tree-format.md`](06-tree-format.md) states the encoding rules).
- **[OBJ-5]** Writing an immutable whose identity already exists in a store
  MUST be a no-op and MUST NOT fail. Reading an immutable MUST verify that
  the bytes returned hash to the identity requested before they are used or
  admitted to any cache. *Gate:* `gate:identity-idempotence`,
  `gate:verify-before-admit`.

### Descriptors

Where an identity is carried outside a store — in a protocol message, a
surface, a token, or a signed statement — it is carried as a descriptor
that names the algorithm so that it cannot be misread under a different
profile.

```text
descriptor = [ algorithm: tstr, domain: tstr, digest: bstr, size: uint ]
```

- **[OBJ-6]** A descriptor MUST carry the algorithm identifier (`blake3` for
  `terrane-v1`), the domain string, the digest, and the encoded size of the
  immutable in bytes. A receiver MUST reject a descriptor whose algorithm it
  does not implement rather than attempting a best-effort match. *Gate:*
  `gate:descriptor-strict`.
- **[OBJ-7]** The display form of a descriptor is
  `<algorithm>:<domain>:<lowercase hex digest>`. Size is omitted from the
  display form and is not part of identity.

### Profiles and digest agility

- **[OBJ-8]** A digest algorithm, its output length, and its set of domain
  strings together form a **profile**. A store has exactly one profile,
  recorded as the `store-profile` field of its `CAPABILITIES` record
  ([`13-bucket-layout.md`](13-bucket-layout.md)), and every identity in the
  store belongs to it.
- **[OBJ-9]** Introducing a new digest algorithm MUST be done by registering
  a new profile. A new profile coexists with the old one in separate stores
  and is bridged by import ([`33-migrations.md`](33-migrations.md)); it is
  never a rewrite of identities in place. This is what makes every identity
  in this specification permanent.
- **[OBJ-10]** An implementation MUST NOT accept an identity under a profile
  it was not configured for, even if it can compute that algorithm.

## Chunks

A chunk is the unit of deduplication, transfer, verification, and caching.
Chunk boundaries are chosen by content-defined chunking
([`05-chunking.md`](05-chunking.md)) so that identical runs of bytes in
different files produce identical chunks.

- **[OBJ-11]** A chunk MUST be at least the profile's minimum chunk size and
  at most its maximum, except that the final chunk of an object MAY be
  shorter than the minimum and an empty object consists of exactly one
  zero-length chunk ([`05-chunking.md`](05-chunking.md) CDC rules).
- **[OBJ-12]** A chunk has no metadata of its own. Which objects reference
  it, which packs hold it, and which tenants may see it are properties of
  manifests, indexes, and trees respectively.

## Objects and manifests

An object is the content of one file. Its manifest is an ordered list of
chunk identities with the object's total size and content hashes.

```text
manifest = {
  1: size            ; uint, total plaintext bytes
  2: chunks          ; [* chunk-ref]   chunk-ref = [ digest: bstr, len: uint ]
  3: hashes          ; { * tstr => bstr }  plaintext hashes by algorithm name
  4: media-type      ; tstr, optional
}
```

- **[OBJ-13]** An object's identity is the identity of its manifest under
  the `terrane-manifest-v1` domain, not a hash of the file's plaintext. A
  writer computes it from chunk identities it already knows and never
  re-reads content it has already chunked. *Gate:*
  `gate:object-identity-from-manifest`.
- **[OBJ-14]** A manifest MUST carry the plaintext BLAKE3 hash of the whole
  file under the key `blake3` in `hashes`. It SHOULD carry `sha256`. It MAY
  carry further registered hashes (for example a git blob identifier under
  `git-blob-sha1` or `git-blob-sha256`) when a property on the root requires them
  ([`08-properties.md`](08-properties.md),
  [`10-derived-data.md`](10-derived-data.md)). Registered hash names are in
  [`reference/property-registry.md`](reference/property-registry.md).
- **[OBJ-15]** The sum of `len` over `chunks` MUST equal `size`. A reader
  MUST reject a manifest that violates this before fetching any chunk.
- **[OBJ-16]** A file whose plaintext is at most the profile's minimum chunk
  size is a single chunk and needs no manifest. Its entry in a tree names
  the chunk identity directly with an inline size
  ([`06-tree-format.md`](06-tree-format.md)). Such a file has no object
  identity distinct from its chunk identity, and its plaintext hashes, when
  required, are carried as entry attributes.
- **[OBJ-17]** Two entries in any trees that name the same object identity
  are the same content. Equality of objects is equality of identities;
  implementations MUST NOT compare content to decide equality.

### Media types

- **[OBJ-18]** A manifest MAY carry a media type. It is advisory for
  surfaces and classification and is not part of identity semantics beyond
  being encoded bytes. Registered media types are in
  [`reference/property-registry.md`](reference/property-registry.md)
  §media types; an unregistered media type is preserved verbatim and treated as
  `application/octet-stream` by surfaces that do not know it.

## Trees

A tree is a map from path to entry, encoded as prolly-tree nodes
([`06-tree-format.md`](06-tree-format.md)). Its identity is the identity of
its root node. Because node boundaries are content-defined, two trees with
the same entries have the same root identity regardless of the sequence of
operations that produced them (history independence).

- **[OBJ-19]** A tree's identity MUST be the identity of its root node
  under the `terrane-node-v1` domain. A root node and a non-root node are
  encoded identically; whether a node is a root is a property of how it is
  referenced, not of the node.
- **[OBJ-20]** A tree MUST NOT contain a cycle of `tree` entries. A writer
  MUST reject a graft that would create one; a reader that detects one MUST
  fail the resolution rather than loop. *Gate:* `gate:tree-acyclic`.

## Commits

A commit binds a tree root to its history and its provenance
([`09-refs-and-commits.md`](09-refs-and-commits.md) defines the encoding
and semantics).

- **[OBJ-21]** A commit's identity MUST be the identity of its canonical
  encoding under `terrane-commit-v1`. It covers the tree root, the ordered
  parent list, the provenance record, the message, the profile, and the
  timestamp; it does not cover any signature, which is carried beside the
  commit ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)).

## Refs

A ref is a name bound to a commit identity, changed only by conditional
write at its authority ([`09-refs-and-commits.md`](09-refs-and-commits.md)).

- **[OBJ-22]** A ref name MUST be a UTF-8 string matching the grammar in
  [`09-refs-and-commits.md`](09-refs-and-commits.md). Ref values are never
  content-addressed; a ref is identified by its name and versioned by its
  sequence number and epoch.

## Containers

Packs, per-pack indexes, merged indexes, filters, and bundles are
immutables in their own domains. They exist so that many small immutables
can be stored and fetched as few large ones. They are defined in
[`12-pack-format.md`](12-pack-format.md).

- **[OBJ-23]** A container's identity MUST NOT appear in any tree, commit,
  or ref. A namespace is defined entirely by chunk, manifest, node, and
  commit identities, so that repacking, reindexing, and re-bundling never
  change what a namespace means. *Gate:* `gate:containers-not-in-identity`.

## Interactions

- [`05-chunking.md`](05-chunking.md) defines chunk boundaries and sizes.
- [`06-tree-format.md`](06-tree-format.md) defines node encoding, the
  canonical CBOR rules, and inline chunk entries.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines commit encoding
  and ref grammar.
- [`10-derived-data.md`](10-derived-data.md) defines how additional hashes
  and classifications are computed and stored per object.
- [`12-pack-format.md`](12-pack-format.md) defines the containers.
- [`reference/terrane-v1.cddl`](reference/terrane-v1.cddl) is the normative
  encoding for every kind but chunk and pack.

## Informative: why the object identity is the manifest hash

Identifying an object by a hash of its plaintext would force every commit to
re-read whole files even when every chunk was already known, because
content-defined chunk boundaries do not align with the internal block
structure of a tree-mode hash. Identifying an object by its manifest lets a
writer compute the identity from chunk identities alone, while the plaintext
hashes carried in the manifest still let any consumer that needs a
whole-file digest verify one without re-chunking.
[`39-decision-register.md`](39-decision-register.md) records the decision.
