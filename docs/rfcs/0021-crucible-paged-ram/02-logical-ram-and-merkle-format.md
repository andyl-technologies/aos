# 02 - Logical RAM and the canonical Merkle format

This chapter specifies logical digest edition 1. It is a new construction;
the suffix `v1` does not mean compatibility with the existing flat RAM SHA-256
definition. Production consumers require the coordinated definition cutover
in [chapter 09](09-security-and-cutover.md).

## 2.1 Logical topology and byte ownership

A machine exposes an admitted inventory of uniquely owned RAM regions. A
region ID is a stable machine-profile identifier, not a host address, process
ID, RAMBlock pointer, allocation order, filesystem path, or random token.
Examples are `machine.ram` and `device.virtio-net.0.ram`. The mapping from
QEMU objects to region IDs is part of the admitted machine profile and must
be reproducible across launches, restores, and hosts. An alias references an
owner; it does not create a second independent region copy.

- **[RAM-1]** Each region ID MUST be a well-formed UTF-8 byte string of
  length 1 through 255, without Unicode code points U+0000 through U+001F or
  U+007F. IDs MUST be compared and sorted by unsigned UTF-8 bytes without
  locale collation or Unicode normalization. Exact duplicate IDs MUST be
  rejected. Visually similar but byte-distinct IDs are different identities;
  implementations SHOULD use an ASCII machine-profile registry for readability.
- **[RAM-2]** Every region MUST have a positive unsigned 64-bit logical byte
  length, one class, and the coverage mask specified below. All RAM-backed
  state MUST have an explicit owner and classification before execution.
  Unknown, overlapping independently owned, or unclassified blocks MUST
  fail admission. Physical aliases MUST resolve to their canonical owner.
- **[RAM-3]** Logical pages MUST have size 4,096 bytes independently of the
  host base page, huge-page choice, QEMU target page, or RAMBlock page size.
  The last page MUST include only the valid bytes within the region. Unmapped
  host padding MUST NOT be hashed or exposed as guest RAM.

Class values and masks are fixed for this edition:

| Class code | Name | Mask | Meaning |
| --- | --- | --- | --- |
| 1 | `mutable-main` | 7 | Ordinary writable guest-observable RAM |
| 2 | `mutable-device` | 7 | Guest-observable mutable RAM-backed device state |
| 3 | `immutable-image` | 6 | RAM-backed bytes proven immutable for the admitted execution |
| 4 | `continuation-private` | 6 | RAM-backed reconstruction state without guest-observable mutable bytes |

Mask bits 0, 1, and 2 select execution, exact, and lifecycle scopes,
respectively. Other bits and other class/mask combinations are invalid in
this edition. `continuation-private` is not permission to omit device state
from execution identity: its complete deterministic device representation must
be committed by the enclosing non-RAM fingerprint. A block containing any
guest-observable mutable bytes is class 1 or 2 as appropriate.

- **[RAM-4]** An execution fingerprint MUST commit to every guest-observable
  mutable RAM byte through the execution scope. Bytes classified as immutable
  MUST be committed through an authenticated immutable launch/image closure
  bound by the enclosing machine identity. A mechanism that can subsequently
  mutate those bytes MUST either classify them as mutable before admission or
  perform an explicit coherent topology/classification change before writing.
  Mutable ROM backing, debugger writes, and fault injection MUST NOT escape
  identity merely because a normal guest write is disallowed.
- **[RAM-5]** Exact and lifecycle scopes MUST cover the complete admitted
  inventory. Exact checkpoints MUST retain readable contents or authenticated
  immutable reconstruction references for every included region. Lifecycle
  roots seal the same contents for retained sources; they do not substitute
  for CPU/device/plugin/host continuation state in the complete source seal.

The complete topology includes classes omitted from execution scope. Thus an
execution root commits to their presence and classification even though it
does not hash their contents. Guest physical address mappings, memory-region
aliases, and device decoding remain committed in canonical machine/device
state outside RAM. The mapping contract MUST prevent exchanging one backing
owner for another without changing the relevant complete machine identity.
Host virtual addresses and operational topology generations are excluded.

## 2.2 Encoding primitives

`H(x)` is BLAKE3 in its default unkeyed hash mode over the exact byte string
`x`, producing exactly 32 raw bytes. This RFC calls that fixed construction
`blake3-256-unkeyed`; it follows
[the BLAKE3 specification, version 1.0.0](https://c2sp.org/BLAKE3@v1.0.0).

Implementations MUST use the default unkeyed mode and exactly the first 32
output bytes. Keyed hashing, derive-key mode, a different output length, and
runtime negotiation of another primitive MUST NOT be used for this edition.
The explicit tags below provide application domain separation. Portable, SIMD,
incremental, and parallel implementations MUST produce identical bytes for
the same input. BLAKE3's internal chunk tree is part of the primitive; it does
not replace the region/page tree or permit substituting internal chaining
values for `H(x)` output.

`||` means byte concatenation. `U8`, `U32`, and `U64` encode unsigned integers
in exactly 1, 4, and 8 bytes, respectively, most significant byte first.
`S(s) = U32(length(s)) || s`, where `s` is the exact UTF-8 byte string.
No terminator follows `S`. Hashes inside preimages are raw bytes, not hex text.

`T(name)` is the ASCII byte string `crucible.ram.` followed by the lowercase
ASCII name, `.v1`, and one zero byte. Valid names used here are `page`, `leaf`,
`empty`, `node`, `region-tree`, `topology`, and `root`. Domain separation is
part of the contract; implementations MUST NOT use a generic concatenation
without these tags. Textual hex presentations are lowercase, exactly 64
characters, and are not part of the binary encoding.

The topology inventory is sorted by region ID. An inventory record is:

```text
RegionDescriptor = S(region_id) || U8(class) || U8(mask) || U64(logical_length)
Inventory = U32(region_count) || concatenation of sorted RegionDescriptors
LogicalTopologyDigest = H(T("topology") || U32(4096) || Inventory)
```

Edition 1 permits at most 4,096 regions in a manifest. The byte format has a
32-bit count to make its interpretation unambiguous; an encoded value beyond
the edition limit is invalid. Actual machine admission must have tighter
resource bounds where necessary. A zero-region inventory is permitted only
as a mathematical/test-vector input; an executable machine MUST have at
least one admitted region.

- **[RAM-6]** Receivers MUST reject malformed UTF-8, forbidden IDs, duplicate
  or nonascending records, invalid classes/masks, zero lengths, excessive
  counts, invalid digest lengths, arithmetic overflow, and unexpected trailing
  bytes in an encoded record. Decoding MUST NOT allocate based solely on an
  unauthenticated count. Aggregate logical length and traversal work MUST fit
  admitted limits before materialization.

## 2.3 Page and ordered tree construction

For a page containing `v` valid bytes, where `1 <= v <= 4096`:

```text
PageDigest = H(T("page") || U32(v) || bytes[0:v])
LeafDigest = H(T("leaf") || PageDigest)
EmptyLeafDigest = H(T("empty"))
InnerDigest(h, left, right) = H(T("node") || U32(h) || left || right)
```

`PageDigest` deliberately excludes page coordinate, owner, scope, dirty epoch,
and storage representation. Identical valid bytes with the same valid length
have the same identity across positions. A three-byte page `abc` is distinct
from a full page whose first three bytes are `abc` and whose remainder is zero.
A real zero page is an ordinary valid page; the empty leaf represents no page.

For a region with logical length `L`, let `n = 1 + floor((L - 1) / 4096)`.
Let `m` be the least power of two greater than or equal to `n`, and let
`height = log2(m)`. Construct exactly `m` leaves: leaves `0` through `n-1`
are valid page leaf digests in ascending page-index order; remaining leaves
are `EmptyLeafDigest`. Reduce adjacent pairs, left before right. The first
parent level uses `h=1`, and the final parent uses `h=height`. For `n=1`,
the tree node is the single real leaf and no inner node is computed.

```text
RegionTreeDigest = H(T("region-tree") || U64(L) || U64(n)
                     || U32(height) || tree_node_digest)
```

This fixed geometry prevents alternative padding or tree balancing from
producing alternate valid encodings. Binding height in each inner preimage
also separates equal child digests at different tree levels. The maximum
region length yields `n <= 2^52` and `height <= 52`; implementations must
compute `m` without intermediate overflow and must apply much smaller admitted
resource limits. There is no page with valid length zero.

- **[RAM-7]** Every scope consumer MUST use this page and tree construction.
  Leaf order MUST bind placement through tree structure. Sparse encodings,
  cached subtrees, implicit zero ranges, compression, and duplicate sharing
  MUST produce exactly the same result as the expanded construction.
- **[RAM-8]** Sparse zero declarations MUST establish real zero-page content
  and exact valid length. Missing objects, absent descriptors, skipped ranges,
  and padding MUST NOT be interpreted as zero content. Reused subtrees MUST
  have the required height and valid geometry at the destination position.

## 2.4 Scoped root construction

The only valid scope tags are the exact ASCII byte strings `execution`,
`exact`, and `lifecycle`. Select inventory records whose coverage mask has
the scope bit. Preserve inventory order. The selected-record encoding is:

```text
ScopedRegion = RegionDescriptor || RegionTreeDigest
RamRootDigest = H(T("root") || U32(1) || U32(4096) || S(scope)
                  || LogicalTopologyDigest || U32(selected_region_count)
                  || concatenation of sorted ScopedRegions)
```

The explicit edition value `1` is included even though tags also carry `v1`.
It belongs to this encoding, not to the whole checkpoint or SHM ABI version.
Scope is part of root identity. Exact and lifecycle roots therefore differ
even when their region sets and contents are identical. A valid receiver has
the complete inventory, recomputes its digest, derives the selected set,
and verifies that every selected descriptor and tree occurs exactly once.
An empty execution selection is mathematically valid but cannot satisfy
an ordinary machine profile requiring mutable guest RAM.

- **[RAM-9]** Portable root records MUST include the complete validated
  inventory, scope, selected region roots, and edition, sufficient to recompute
  the expected `RamRootDigest`. A supplied topology digest alone MUST NOT
  authorize a selectively omitted region. A receiver MUST reject wrong scope,
  descriptors inconsistent with inventory, omitted/extra roots, or geometry
  inconsistent with region lengths.
- **[RAM-10]** Host residency, native addresses, host page geometry, policy
  revisions, process/node incarnations, page versions, dirty generations,
  storage object IDs, and representation metadata MUST NOT enter logical RAM
  hash preimages. They MUST remain separately validated operational state.

Equality of roots is a content commitment under BLAKE3's usual assumptions,
not evidence of storage availability, execution authorization, or equality
of CPU/device state. The root MUST be bound into the enclosing versioned
machine fingerprint, checkpoint, or lifecycle seal. It is never a standalone
resume authorization.

## 2.5 Proofs, portable nodes, and storage identities

A page proof supplies coordinate, valid length, page bytes or authenticated
page reference, and sibling digests from leaf level to region tree root.
Sibling position follows the low-order bits of the page index; it is not
caller-selected. The verifier recomputes the leaf, each height-bound parent,
the region wrapper, and the selected scoped-root record. Proof depth must
equal the admitted region height. A valid page proof does not establish that
the other pages are available or that the complete root is retained.

A verifier MUST require `page_index < n` and
`valid_length = min(4096, L - 4096 * page_index)` with checked arithmetic.
Proofs for padding positions MUST be rejected. Verification of the enclosing
scope root additionally requires the authenticated complete root record,
including the other selected region roots; a region-local sibling path alone
cannot reconstruct the flat ordered scoped-root preimage.

Portable structural nodes must explicitly identify leaf/inner kind, height,
children, and any storage references; their exact representation belongs to
the store schema in chapter 07. They may contain `PageObjectId` values even
though those values are excluded from logical hash preimages. Different
canonical serialized RAM objects can share a logical digest while having
different `ContentId` values. Packing, compression, encryption, and placement
of the same canonical plaintext object do not change its `ContentId`; their
physical authentication remains a separate storage obligation. An implementation
must validate structural fields against the logical preimage, not trust them
because their canonical object authentication is valid.

- **[RAM-11]** Logical BLAKE3-256 digests MUST NOT be substituted for existing
  CAS `ContentId` values. Each preserved or transferred representation MUST
  be authenticated by its storage contract and its decoded logical page/tree
  relationship. A compressed, packed, encrypted, or re-encoded page MUST retain
  the same logical digest when its decoded valid bytes are unchanged.

Both logical RAM digests and existing CAS identities now use BLAKE3. Their
preimages, domains, types, and responsibilities still differ. A shared primitive
does not make a page digest the identity of its serialized object, and a
canonical object hash does not establish the page's placement in a RAM root.

- **[RAM-12]** Internal persistent trees MAY share immutable nodes across
  versions and positions. Publication MUST bind an immutable coherent view.
  Dirty candidates that revert to identical contents MAY retain the previous
  page identity and avoid ancestor changes. Operational version equality
  MUST NOT be treated as proof of logical content equality.

## 2.6 Reference algorithm and vectors

The following pseudocode defines tree reduction. It assumes validated input;
production implementations must perform the checks above and avoid materializing
the full expanded tree when sparse or persistent construction is available.

```python
def region_tree(length, page_digests):
    count = 1 + (length - 1) // 4096
    assert len(page_digests) == count
    width = 1 << (count - 1).bit_length()
    nodes = [H(T("leaf") + digest) for digest in page_digests]
    nodes += [H(T("empty"))] * (width - count)
    height = 0
    while len(nodes) > 1:
        height += 1
        nodes = [H(T("node") + U32(height) + nodes[i] + nodes[i + 1])
                 for i in range(0, len(nodes), 2)]
    return H(T("region-tree") + U64(length) + U64(count)
             + U32(height) + nodes[0])
```

[format-vectors.json](format-vectors.json) includes exact preimages where small,
byte-generation descriptions for larger inputs, and expected lowercase digests
for the empty sentinel, a three-byte page, a full zero page, a one-page region,
and a three-page region with padding. It also includes a two-region topology
whose immutable image is absent from the execution selection but present in
exact and lifecycle roots. These cases catch raw/hex confusion, endianness,
partial-page length, scope binding, topology binding, and non-power-of-two
padding. Independent C and Rust production implementations MUST additionally
share negative vectors and maximum-boundary tests; this document does not
make exhaustive test coverage claims.

## 2.7 Metadata and complexity

The expanded padded tree has `2m - 1` nodes, with `m` the next power of two
at or above `n`. For power-of-two regions, storing a 32-byte digest per node
costs approximately 64 bytes per logical page, or 1.5625% of guest RAM, before
references, allocator overhead, region wrappers, and version metadata. For
512 MiB, this is about 8 MiB; for 64 GiB, about 1 GiB. Unfavorable padding can
approach twice that overhead (3.125%); shared padding reduces realized storage
but does not justify omitting the expanded dense bound from admission. An 8-byte
page-version array adds 1 MiB and 128 MiB respectively. One dirty bit per page
adds 16 KiB and 2 MiB per consumer. Sparse zero sharing reduces common initial
state, but admission must account for dense worst cases.

Hashing `k` changed pages is proportional to their valid bytes. A naive ancestor
update is `O(k log n)`; batched persistent rebuilding can avoid repeated work
on common ancestors. Boundary sampling should reuse unchanged nodes. Hashing
on every store is unnecessary and would defeat TCG throughput. Reading all
RAM independently remains a deliberate validation oracle, never the normal
fingerprint implementation for a disk-oriented running campaign.
