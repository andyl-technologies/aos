# 06 — Tree format

This file defines the tree: a persistent, history-independent Merkle map
from path to entry, stored as prolly-tree nodes. It fixes the key space, the
boundary function that makes the structure a function of content alone,
the entry types, and the canonical encoding of nodes. The algebra over trees
is in [`07-tree-algebra.md`](07-tree-algebra.md); this file is the data.

## Overview

A tree is an ordered map. Keys are paths relative to the tree's own root,
bytewise sorted, so that the entries of one directory form a contiguous key
range and a directory listing is a range scan. Values are entries: files,
directories, symbolic links, hard-link identities, and references to other
roots.

The map is stored as a B-tree whose node boundaries are chosen by a rolling
hash over the encoded entries rather than by fill level. Two trees with the
same entries therefore have byte-identical nodes and the same root identity
no matter how they were built ("history independence"), a change to one
entry rewrites O(log n) nodes, and two trees can be compared or merged by
descending only into subtrees whose identities differ.

## Keys

- **[TREE-1]** A key is the path of an entry relative to the root of the
  tree that contains it, as a byte string, with components separated by a
  single `0x2F` (`/`), no leading or trailing separator, no empty
  component, and no component equal to `.` or `..`. Keys are compared as
  unsigned bytes. Index-tree keys are opaque byte strings instead of paths
  (TREE-32, DRV-12); they are also compared as unsigned bytes. *Gate:*
  `gate:tree-keys`.
- **[TREE-2]** A component MUST NOT contain `0x00` or `0x2F`. Components are
  otherwise arbitrary bytes; they are not required to be UTF-8, because
  filesystems are not. Index-tree keys MAY contain any byte, including
  `0x00` and `0x2F`.
- **[TREE-3]** The root directory of a tree has no entry; it is implied. A
  tree with no entries is the empty tree, whose root node is the encoded
  empty leaf.
- **[TREE-4]** Every ancestor directory of an entry MUST be present as a
  `dir` entry, except the implied root. A conflicted ancestor MAY instead
  be a `conflict` entry with at least one `dir` candidate; its descendants
  are conditional on resolving that ancestor to a directory. Resolving to
  a nondirectory MUST remove those descendants. A tree with a file at `a/b` and no
  `dir` entry at `a` is malformed. Index trees have no directory ancestors;
  their keys are opaque. *Gate:* `gate:tree-well-formed`.
- **[TREE-5]** A key MUST NOT have a `tree` entry as a proper prefix
  component path. Entries beneath a `tree` entry belong to the referenced
  root, not to the containing tree.
- **[TREE-6]** The maximum key length is 4 096 bytes and the maximum
  component length is 255 bytes. Implementations MUST reject longer keys at
  construction and at decode. The component limit applies only to path keys;
  an index-tree key is one opaque byte string with the same 4 096-byte cap.

## Entries

An entry is a map with a type and type-specific fields. All entry types
share the optional fields `attrs`, `xattrs`, and `prov`.

| Type | Value | Required fields | Optional fields |
| --- | --- | --- | --- |
| `file` | 1 | `mode`, `size`, `content` | `link-id` |
| `dir` | 2 | `mode` | |
| `symlink` | 3 | `target` | |
| `tree` | 4 | `root` | `props` |
| `whiteout` | 5 | | |
| `conflict` | 6 | `candidates` | `base` |
| `index` | 7 | `targets` | |

```text
entry = {
  1: type,                     ; uint per table above
  ? 2: mode,                   ; uint, low 12 bits of st_mode
  ? 3: size,                   ; uint, plaintext bytes (file)
  ? 4: content,                ; content-ref (file)
  ? 5: target,                 ; bstr, symlink target bytes
  ? 6: root,                   ; bstr .size 32, tree root identity (tree)
  ? 7: props,                  ; { * property-name => property-value } (tree)
  ? 8: link-id,                ; bstr, hard-link identity (file)
  ? 9: attrs,                  ; { * tstr => any }
  ? 10: xattrs,                ; { * bstr => bstr }
  ? 11: prov,                  ; provenance-ref
  ? 12: candidates,            ; [2* entry], conflict candidates in layer order
  ? 13: base,                  ; entry / null, merge base value (conflict)
  ? 14: targets,               ; [+ bstr .size 32], object hashes (index)
}
content-ref = [ 0, chunk: bstr .size 32 ]         ; inline single chunk
            / [ 1, manifest: bstr .size 32 ]      ; object manifest
```

- **[TREE-7]** `mode` carries only permission and type-independent bits:
  the low 12 bits of a POSIX `st_mode` (`rwxrwxrwx`, setuid, setgid,
  sticky). File-type bits are implied by `type`. Surfaces that cannot
  represent a bit MUST report the degradation in status and MUST NOT alter
  the entry ([`26-surfaces.md`](26-surfaces.md)).
- **[TREE-8]** A `file` entry whose `size` is at most the profile's minimum
  chunk size MUST use the inline form of `content-ref` (tag `0`) naming the
  single chunk. A `file` entry whose `size` exceeds the minimum MUST use the
  manifest form (tag `1`). A decoder MUST reject the other combination.
  *Gate:* `gate:tree-well-formed`. *See:* [`04-content-model.md`](04-content-model.md)
  OBJ-16.
- **[TREE-9]** Ownership is not stored in `mode` and is not an entry field.
  User and group identity, where a surface needs them, are attributes under
  the registered names `uid` and `gid`
  ([`reference/property-registry.md`](reference/property-registry.md)), so
  that trees produced for canonical read-only stores carry none and trees
  produced from live filesystems may carry them.
- **[TREE-10]** Timestamps are not entry fields. A surface that must present
  times uses a fixed canonical time unless the root's properties name an
  attribute to present ([`08-properties.md`](08-properties.md)). This keeps
  identity independent of extraction time.
- **[TREE-11]** `link-id` identifies a hard-link set within one tree: two
  `file` entries with equal `link-id` denote one inode. Entries in a set
  MUST have identical `mode`, `size`, `content`, `attrs`, and `xattrs`; a
  decoder MUST reject a set that differs. `link-id` values are opaque and
  MUST be assigned deterministically as the key of the set's first entry in
  key order, so that history independence is preserved. *Gate:*
  `gate:tree-hardlinks`.
- **[TREE-12]** A `symlink` `target` is stored verbatim and is not
  validated, resolved, or normalized. Whether a surface follows it is the
  surface's concern.
- **[TREE-13]** A `tree` entry references another root by identity. The
  referenced root's keys are relative to that root. `props` on the entry
  are the properties of the grafted root as seen from this tree
  ([`08-properties.md`](08-properties.md)); they override, for this graft
  only, any properties recorded with the root elsewhere.
- **[TREE-14]** `attrs` carries writer-supplied and derived attributes by
  registered name. Unregistered names MUST be rejected at commit by a
  writer with the `strict-attrs` property set and MUST be preserved
  verbatim otherwise. Derived attributes that are functions of content are
  additionally stored per object ([`10-derived-data.md`](10-derived-data.md))
  so that they are computed once.
- **[TREE-15]** `xattrs` carries extended attributes as raw name and value
  bytes. Names in the `security.`, `system.`, and `trusted.` namespaces MUST
  NOT be presented by a surface to an unprivileged consumer unless the
  root's properties allow that namespace explicitly.
- **[TREE-16]** An explicit `prov` references the provenance record of a
  verified prior commit that introduced the entry's current content
  ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)). It is set by
  the repository layer at commit and MUST NOT be supplied by a writer.
  New introductions use the containing commit's signed profile-pair
  receipt with origin `current`, leaving `prov` absent to avoid a hash
  cycle. Unchanged entries may inherit verified parent receipts as defined
  by PROV-7; absence alone is not proof of introduction or preservation.

### Layer, merge, and index entries

Three entry types exist for the algebra rather than for consumers.

- **[TREE-30]** A `whiteout` entry hides its key in every lower layer of an
  overlay ([`07-tree-algebra.md`](07-tree-algebra.md)). It carries no
  content, mode, or attributes other than `prov`. A `whiteout` is meaningful
  only in a tree that is a layer of an overlay or the upper of a writable
  exposure; `flatten` removes it, and a surface MUST NOT present it. A tree
  served directly by a surface MUST NOT contain one. *Gate:*
  `gate:tree-well-formed`.
- **[TREE-31]** A `conflict` entry is the value of a key that a merge could
  not resolve ([`07-tree-algebra.md`](07-tree-algebra.md) ALG-17).
  `candidates` holds the candidate entries in the merge's side order, each
  a complete entry of another type, and `base` holds the merge-base value
  or `null` when the key was absent from the base. Candidates MUST NOT
  themselves be `conflict` entries. In a merge conflict, a `whiteout`
  candidate represents an absent side (ALG-17). A surface MUST NOT present a
  `conflict` entry unless its schema declares conflict support.
  A structural directory-versus-nondirectory conflict retains descendants
  under the TREE-4 conditional-directory rule; conflict-aware consumers
  MUST NOT treat those descendants as accessible under a nondirectory side.
- **[TREE-32]** An `index` entry is the value of a key in an index tree
  ([`10-derived-data.md`](10-derived-data.md)): `targets` lists the object
  hashes whose indexed attribute equals the key, in ascending byte order
  without duplicates. Index-tree keys are opaque, nonempty byte strings;
  path grammar and directory ancestors do not apply. Index trees contain
  only `index` entries, and a tree served by a surface MUST NOT contain one.

- **[TREE-35]** The executable `terrane-index/v1` result MUST use the
  contextual Index roles in DRV-30. These specialize TREE-32's value-key
  interpretation: primary keys carry a value and object identity, gap keys
  carry an object identity, and occurrence-route keys carry root-local
  filesystem paths. Every role MUST still contain only type-7 entries;
  route trees MUST NOT add directory markers. Route keys MUST obey TREE-1/2
  and TREE-6's component limit as well as its total limit, without TREE-4's
  directory-ancestor requirement. Primary and gap keys remain opaque.
  Structural `index.occurrences` metadata MUST be interpreted only in its
  registered role and attribute semantic revision; its presence alone MUST
  NOT select a role or turn an ordinary namespace entry into an Index entry.
  Generic retained Index entries and their existing fields, target lists,
  encodings and identities remain valid outside this specialization.
  *Gate:* `gate:canonical-cbor`, `gate:index-tree-maintenance`.

## Node structure

A tree is a B-tree of nodes. Leaf nodes hold entries; internal nodes hold
child references. Every node is an immutable identified under
`terrane-node-v1` ([`04-content-model.md`](04-content-model.md) OBJ-19).

```text
node = {
  1: level,                    ; uint, 0 for leaf
  2: items,                    ; leaf: [* leaf-item]; internal: [* child-ref]
  ? 3: props,                  ; root node only: { * property-name => property-value }
}
leaf-item  = [ key-suffix: bstr, shared: uint, entry ]
child-ref  = [ last-key: bstr, child: bstr .size 32, count: uint, weight: uint ]
```

- **[TREE-17]** Items in a node MUST be in strictly ascending key order. A
  leaf's items are its entries; an internal node's items reference children
  whose key ranges are disjoint and ascending, each labeled by the greatest
  key it contains (`last-key`), the number of entries beneath it (`count`),
  and the total encoded size of the subtree's nodes (`weight`). *Gate:*
  `gate:tree-well-formed`.
- **[TREE-18]** Leaf keys use prefix compression within a node: `shared` is
  the number of leading bytes the key has in common with the previous
  item's full key, and `key-suffix` is the remainder. The first item's
  `shared` MUST be 0. Compression is confined to one node so that any node
  is decodable alone. Internal `last-key` values are stored in full.
- **[TREE-19]** All leaves in a tree MUST be at level 0 and all paths from
  the root to a leaf MUST have equal length; the tree is balanced by
  construction because boundaries are chosen at every level by the same
  procedure over the level below.
- **[TREE-33]** The root node of a tree MAY carry `props`, the property map
  of the root ([`08-properties.md`](08-properties.md)). A non-root node MUST
  NOT carry `props`. Because `props` is part of the root node's bytes, a
  property change changes the root identity and therefore appears in
  `diff`. A `tree` entry's `props` (TREE-13) override the referenced root
  node's `props` for that graft only.
- **[TREE-20]** The `count` and `weight` fields are advisory for sharding
  and cost estimation ([`32-tree-jobs.md`](32-tree-jobs.md),
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md)). A reader
  MUST NOT rely on them for correctness, and a writer MUST compute them
  exactly so that they are part of the canonical bytes.

- **[TREE-34]** Entry `type` values `8` through `15` are reserved for
  special files a live filesystem may need (character and block devices,
  FIFOs, sockets) and for a future native working tree. A 1.0 decoder MUST
  reject them; a later version assigns them without renumbering existing
  types, so a 1.0 tree remains decodable by every later version. *Gate:*
  `gate:tree-well-formed`.

## Boundary function

The boundary function decides where one node ends and the next begins. It
is a function of the encoded items alone, so that the same sorted item
sequence always yields the same nodes.

```text
for each item i in key order:
  encode i relative to the node's previous key; let L be its stored length
  if S + L > MAX_NODE:
    close the nonempty node before i
    re-encode i as the first item of the new node; recompute L
  if L > MAX_NODE:            reject the item
  append i; S = S + L
  h = low 32 bits of BLAKE3 over the full-key canonical encoding of i
  T = min(2^32, floor(B(S) * L / 8))
  if S == MAX_NODE:           close the node after i
  else if S >= MIN_NODE and h < T:
                               close the node after i
  else:                        continue
```

`S` is the number of stored item bytes in the current node, excluding node
framing. `L` is the current item's actual stored length, including prefix
compression. The full-key encoding is used only for hashing. A split before
an item resets prefix compression before the item is re-encoded. The final
nonempty node closes at the end of the sequence.

- **[TREE-21]** The rolling hash is the low 32 bits of BLAKE3 over the
  canonical encoding of the item (for a leaf, the encoded `leaf-item` with
  `shared` set to 0 and the full key; for an internal node, the encoded
  `child-ref`). Using the full key makes the boundary decision independent
  of prefix compression state. *Gate:* `gate:tree-boundaries`.
- **[TREE-22]** `MIN_NODE` is 4 KiB and `MAX_NODE` is 64 KiB of stored
  encoded item bytes. The base threshold `B(S)` rises linearly from `2^20`
  at `MIN_NODE` to `2^24` at 32 KiB and stays at `2^24` until `MAX_NODE`.
  The per-item comparison threshold MUST be
  `min(2^32, floor(B(S) * L / 8))`, using integer arithmetic, where `S`
  includes the current item and `L` is its stored encoded length. Scaling
  by item bytes prevents large entries from reducing the split frequency
  per byte. The target mean of complete nodes is 8 KiB to 16 KiB for the
  sequential, shared-prefix, and hash-like fixtures of
  `gate:tree-node-distribution`, applied separately to each fixture level
  with at least 100 complete nodes. Smaller samples, final tail nodes, and
  the root MUST be reported but do not establish a distribution; the hard
  size bound and deterministic replay checks still apply to every node. The base table and comparison vectors are in
  [`reference/golden-vectors.md`](reference/golden-vectors.md) §node-boundaries.
  A builder MUST split before an item that would exceed `MAX_NODE`, and
  MUST reject an item whose encoding as a node's first item exceeds that
  bound. *Gate:* `gate:tree-node-distribution`.
- **[TREE-23]** A node MUST close after its last item regardless of the
  boundary function. The same procedure MUST be applied at every level: the
  `child-ref` items of level *k* + 1 are formed from the nodes of level *k*
  in order and chunked by the same rule, until one node remains, which is
  the root. A single leaf that is the entire tree is the root at level 0.
- **[TREE-24]** The procedure MUST be deterministic and history
  independent: for a given profile and a given sorted item sequence, every
  implementation MUST produce identical nodes and an identical root
  identity. *Gate:* `gate:tree-history-independence`.

## Canonical encoding

Every node, entry, manifest, commit, bundle, and other CBOR-encoded
immutable uses one deterministic profile so that independent
implementations compute identical identities. The schema is
[`reference/terrane-v1.cddl`](reference/terrane-v1.cddl); the rules below
constrain the encoder beyond CDDL.

- **[TREE-25]** Encoding is CBOR (RFC 8949) under the deterministic rules
  of its section 4.2, with these additional restrictions:
  - definite-length arrays, maps, byte strings, and text strings only;
  - the shortest encoding for every integer and every length;
  - no floating-point values, no bignums, no tags, no indefinite items,
    and no simple values other than `true`, `false`, and `null` where the
    schema permits them;
  - map keys are unsigned integers except where the schema names a text
    or byte-string keyed map, and keys are sorted by their encoded bytes
    ascending; duplicate keys are a decode error;
  - text strings are valid UTF-8 and appear only where the schema says
    text; filesystem names are byte strings.
  *Gate:* `gate:canonical-cbor`.
- **[TREE-26]** A decoder MUST reject an object containing a map key the
  schema does not define. Forward compatibility is provided by new media
  types and profile versions, not by ignoring unknown fields, because an
  ignored field would still be part of the identity and could carry
  meaning the decoder failed to enforce.
- **[TREE-27]** A decoder MUST enforce limits on claimed lengths before
  allocating: no byte string, text string, array, or map longer than the
  limits in [`reference/terrane-v1.cddl`](reference/terrane-v1.cddl), and
  no node larger than `MAX_NODE` plus its framing. A decoder MUST NOT trust
  a claimed length to size an allocation.
- **[TREE-28]** An encoder MUST produce bytes that its own decoder accepts
  and re-encodes identically. *Gate:* `gate:canonical-cbor`.

## Limits

| Quantity | Limit |
| --- | --- |
| key length | 4 096 bytes |
| component length | 255 bytes |
| symlink target | 4 096 bytes |
| xattr name | 255 bytes |
| xattr value | 64 KiB |
| attributes per entry | 256 |
| encoded node size | 64 KiB plus framing |
| tree depth (levels) | 16 |
| `tree`-entry nesting depth | 64 |

- **[TREE-29]** An implementation MUST enforce the limits above at
  construction and at decode. A tree exceeding a limit is malformed.

## Interactions

- [`04-content-model.md`](04-content-model.md) defines node identity and
  the inline-chunk rule.
- [`07-tree-algebra.md`](07-tree-algebra.md) defines operations that
  produce trees and relies on TREE-24 for O(delta) diff and merge.
- [`08-properties.md`](08-properties.md) defines the `props` map on `tree`
  entries.
- [`10-derived-data.md`](10-derived-data.md) defines derived attributes.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md) defines the
  provenance reference.
- [`27-surface-fuse.md`](27-surface-fuse.md) and
  [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md) compile
  trees into node-local indexes and images; their formats are replaceable
  and are not part of identity.
- [`reference/terrane-v1.cddl`](reference/terrane-v1.cddl) is normative for
  every structure sketched here.

## Informative: keys relative to the root

Keying entries by full absolute path would make grafting a root beneath a
new prefix an O(n) rewrite of every key. Keying relative to the containing
root makes a graft a single `tree` entry and keeps the referenced root's
nodes byte-identical wherever it is mounted, which is what lets one root be
shared by many namespaces and lets authority, storage, and properties be
scoped to roots. The cost is that a lookup crosses a `tree` entry by
resolving the referenced root, which is one additional node fetch per graft
level and is bounded by the nesting limit.
