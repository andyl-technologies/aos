# Reference: golden vectors

Byte-exact test vectors for the `terrane-v1` profile. Every vector below was
generated from the rules in the owning file and is normative when a
requirement cites it ([`../00-conventions.md`](../00-conventions.md)).
An implementation MUST reproduce each vector exactly; `gate:golden-vectors`
([`../36-testing-and-conformance.md`](../36-testing-and-conformance.md)
TEST-1) checks every one.

Hex is lowercase. CBOR is shown in diagnostic notation and as the exact
canonical bytes ([`../06-tree-format.md`](../06-tree-format.md) TREE-25).
Identities are BLAKE3-256 over `domain || 0x00 || bytes`
([`../04-content-model.md`](../04-content-model.md) OBJ-2). Signatures use
Ed25519 with the RFC 8032 §7.1 test keys so that any implementation can
regenerate them.

## Test keys

| Key | Secret seed (hex) | Public key (hex) |
| --- | --- | --- |
| `k1` (issuer) | `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60` | `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` |
| `k2` (ephemeral) | `4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb` | `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c` |

These keys are public and MUST NOT be trusted by any store outside a
conformance suite.

## Gear table

The FastCDC gear table ([`../05-chunking.md`](../05-chunking.md) CDC-1) is
derived from the profile seed:

```text
bytes   = BLAKE3-XOF( "terrane-gear-v1" || 0x00 || seed, 2048 bytes )
gear[i] = u64le( bytes[8*i .. 8*i + 8] )        for i in 0 .. 256
```

The `cdc-1m` profile ([`property-registry.md`](property-registry.md)
§chunk profiles) uses the all-zero 32-byte seed. For that seed:

| i | `gear[i]` |
| --- | --- |
| 0 | `0x15f23553a70da356` |
| 1 | `0x9700318b430e40f3` |
| 2 | `0x70cd1174e9697d43` |
| 3 | `0x0026abb73a8487ac` |
| 4 | `0xae9e6f49c0846cb3` |
| 5 | `0xafd4bb99913bf95f` |
| 6 | `0xba377b75cd23033d` |
| 7 | `0xb0cd9e1ce544864c` |

BLAKE3 of the full 2 048-byte table: `22e8d10aa13d65d681fa4ff159d1151c11c90f652bc059d4418c3f463f49b14c`.

Chunk-boundary vectors over a synthetic stream (a full FastCDC run with
normalization level 2 over the `cdc-1m` parameters) are produced by the
conformance suite's reference chunker and checked by `gate:cdc-boundaries`;
they are not reproduced here because they run to hundreds of boundaries.

## Chunk identities

Domain `terrane-chunk-v1`.

| Input | Identity |
| --- | --- |
| empty (CDC-5) | `b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc0` |
| `hello, terrane\n` (15 bytes) | `9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0` |

## Descriptor

Descriptor of the 15-byte chunk above (OBJ-6):

```text
["blake3", "terrane-chunk-v1", h'9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0', 15]
```

```hex
8466626c616b65337074657272616e652d6368756e6b2d763158209479e1e574
91078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba00f
```

Display form: `blake3:terrane-chunk-v1:9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0`.

## Leaf node with one inline file

Entry for `hello.txt`, mode `0644`, 15 bytes, inline chunk (TREE-8):

```text
{1: 1, 2: 420, 3: 15, 4: [0, h'9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0']}
```

```hex
a40101021901a4030f04820058209479e1e57491078eb09f9decc2c56c63110c
372de01557d73560dbc2ba9f3ba0
```

Leaf item `[h'hello.txt', 0, entry]` and the node `{1: 0, 2: [item]}`:

```hex
a201000281834968656c6c6f2e74787400a40101021901a4030f048200582094
79e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0
```

| Quantity | Value |
| --- | --- |
| node identity (domain `terrane-node-v1`) | `9366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c20bbc392` |
| rolling hash of the item (TREE-21, low 32 bits of BLAKE3 over the encoded item, little-endian) | `1677076257` |

Because the node is the whole tree, it is the root, and the tree identity
equals the node identity (OBJ-19).

## Node boundaries

`boundary-probability(S)` for encoded size `S` (TREE-22): `1/4096` at
`MIN_NODE` = 4 096, rising linearly to `1/256` at 32 768, constant to
`MAX_NODE` = 65 536. The comparison is `(h mod 2^32) < T(S)` where
`T(S) = floor(p(S) * 2^32)`.

| S (bytes) | p(S) | T(S) |
| --- | --- | --- |
| 4096 | 0.000244141 | 1048576 |
| 8192 | 0.000767299 | 3295524 |
| 12288 | 0.001290458 | 5542473 |
| 16384 | 0.001813616 | 7789421 |
| 20480 | 0.002336775 | 10036370 |
| 24576 | 0.002859933 | 12283318 |
| 28672 | 0.003383092 | 14530267 |
| 32768 | 0.003906250 | 16777216 |
| 49152 | 0.003906250 | 16777216 |
| 65536 | 0.003906250 | 16777216 |

Between table rows `T(S)` is linear in `S` and MUST be computed exactly as
`floor((2^20 + (S - 4096) * (2^24 - 2^20) / 28672))` for
`4096 <= S <= 32768`, using integer arithmetic.

## Manifest (encoding vector)

A 300 000-byte plaintext whose byte `i` is `i mod 251`, split into two
chunks of 262 144 and 37 856 bytes. This vector fixes the manifest encoding
and identity (OBJ-13); the split is not a chunker output and is not a
`gate:cdc-boundaries` vector.

| Quantity | Value |
| --- | --- |
| chunk 1 identity | `5860ee5a4a84d54950c417a0636b35e6e3fbbc1d52f8cf9efb810f0031278d67` |
| chunk 2 identity | `39e1233664267460cfc8a61ceaff03ed99aa78475f4f5cb17ce2a2181c7b8746` |
| plaintext BLAKE3 | `6cc9dce05d4cff8c5bef5c5a24681e42b13f03e34a0bc5e66f65a91d48c944fa` |
| plaintext SHA-256 | `3c65ea93424a9c362fec0e3a69ea36031e8a358441479dd665cc6110eabe7b08` |

```text
{1: 300000,
 2: [[h'<chunk 1>', 262144], [h'<chunk 2>', 37856]],
 3: {"blake3": h'<plaintext BLAKE3>', "sha256": h'<plaintext SHA-256>'}}
```

Canonical bytes (171 bytes; note the text-keyed map in key 3
sorts `"blake3"` before `"sha256"` by encoded bytes):

```hex
a3011a000493e002828258205860ee5a4a84d54950c417a0636b35e6e3fbbc1d
52f8cf9efb810f0031278d671a0004000082582039e1233664267460cfc8a61c
eaff03ed99aa78475f4f5cb17ce2a2181c7b87461993e003a266626c616b6533
58206cc9dce05d4cff8c5bef5c5a24681e42b13f03e34a0bc5e66f65a91d48c9
44fa6673686132353658203c65ea93424a9c362fec0e3a69ea36031e8a358441
479dd665cc6110eabe7b08
```

Object identity (domain `terrane-manifest-v1`): `012fb6dded774e62a96a38b832da9f2f8f7eb5caa5dddefd2b405a4602b53e0c`.

## Commit

A root commit of the leaf node above, by workload `ci-job` under issuer
`issuer.example`, token id `01..10`, at time 1 760 000 000, writer epoch 1,
source `built` (1):

```text
{1: h'<node identity>',
 2: [],
 3: {1: "issuer.example", 2: h'0102030405060708090a0b0c0d0e0f10',
     3: "ci-job", 4: 2, 6: "terrane-cli/commit", 7: 1760000000,
     8: 1, 9: 1},
 4: 1760000000,
 5: "initial",
 6: {1: 1, 2: "cdc-1m"}}
```

Signature preimage (key 8 absent, PROV-3):

```hex
a60158209366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c
20bbc392028003a8016e6973737565722e6578616d706c650250010203040506
0708090a0b0c0d0e0f10036663692d6a6f620402067274657272616e652d636c
692f636f6d6d6974071a68e7780008010901041a68e778000567696e69746961
6c06a2010102666364632d316d
```

| Quantity | Value |
| --- | --- |
| BLAKE3 of the preimage | `b3044fe851beb31a8462050527e959ca55ad1ab6cca5a3738986c216bda258cd` |
| Ed25519 signature by `k1` over the preimage | `0b1b8d248ff55846868046c342ee3ae5ca049862cec1c4c8ad9207f6fab19e73a6f5013337b587370634e366d70998ed715d1105f7ba505f6f519bd967dd710d` |

Full commit with key 8:

```hex
a70158209366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c
20bbc392028003a8016e6973737565722e6578616d706c650250010203040506
0708090a0b0c0d0e0f10036663692d6a6f620402067274657272616e652d636c
692f636f6d6d6974071a68e7780008010901041a68e778000567696e69746961
6c06a2010102666364632d316d0858400b1b8d248ff55846868046c342ee3ae5
ca049862cec1c4c8ad9207f6fab19e73a6f5013337b587370634e366d70998ed
715d1105f7ba505f6f519bd967dd710d
```

Commit identity (domain `terrane-commit-v1`): `c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4cede9c579d6`.

## Ref record and reflog record

`RefRecord` for that commit at `seq` 1, `writer_epoch` 1, home region
`eu-west-1`:

```text
{1: h'<commit identity>', 2: 1, 3: 1, 4: {1: "eu-west-1"}}
```

```hex
a4015820c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4ced
e9c579d60201030104a1016965752d776573742d31
```

`RefLogRecord` for the same advance, no previous commit, principal `ci-job`,
reason `commit`:

```hex
a501a4015820c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a
4cede9c579d60201030104a1016965752d776573742d3102f6036663692d6a6f
620466636f6d6d6974051a68e77800
```

Ref records are not content-addressed; these vectors fix encoding only.

## Attribute record

`AttrRecord` binding `hash.sha256` of the manifest object above, produced by
function `sha256/1` under the commit above:

```text
{1: h'<object identity>', 2: "hash.sha256", 3: h'<plaintext SHA-256>',
 4: "sha256/1", 5: h'<commit identity>'}
```

```hex
a5015820012fb6dded774e62a96a38b832da9f2f8f7eb5caa5dddefd2b405a46
02b53e0c026b686173682e7368613235360358203c65ea93424a9c362fec0e3a
69ea36031e8a358441479dd665cc6110eabe7b0804687368613235362f310558
20c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4cede9c579
d6
```

Record identity (domain `terrane-attr-v1`): `d66a8b356e79357277b5ef355d78ec061591ce79a13a3ea68675251a454bf592`.

## Capability token

A two-block token: an authority block issued by `k1` for workload `ci-job`
in group `builders`, granting `read | fork | commit` (bitmask 7) on
`refs/heads/pr/**` until 1 760 003 600, with next-key `k2`; then an
attenuation block signed by `k2` adding the caveats
`ref(refs/heads/pr/1234)` and `epoch(refs/heads/pr/1234, 1)`.

Authority block preimage (key 12 absent):

```hex
a9016e6973737565722e6578616d706c6502626b31036663692d6a6f62040205
81686275696c64657273061a68e7861008500102030405060708090a0b0c0d0e
0f1009818270726566732f68656164732f70722f2a2a070b58203d4017c3e843
895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
```

Signature by `k1`: `7239961b2b42911f2f2ad53e5b8715d82f18ba850cad724863832e43d45bbd4ccffd924ffa1189b7695a7d6c610fb766ff7ea30a26cd69924f9f140edac5f609`.

Attenuation block preimage (key 6 absent):

```hex
a20482826372656672726566732f68656164732f70722f31323334836565706f
636872726566732f68656164732f70722f31323334010558203d4017c3e84389
5a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
```

Signature by `k2` over `auth_sig || att_pre`: `3fda3b61fb042cf3fe81e027fb7968fef6f8e40fb59e7ccb98117c97392ba0bbd5aa8e92a5faf958af1cb6f61f739b5c6cec2e194e644058ea2d4f8989ac700c`.

Complete token `[authority-block, attenuation-block]`:

```hex
82aa016e6973737565722e6578616d706c6502626b31036663692d6a6f620402
0581686275696c64657273061a68e7861008500102030405060708090a0b0c0d
0e0f1009818270726566732f68656164732f70722f2a2a070b58203d4017c3e8
43895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c0c58407239
961b2b42911f2f2ad53e5b8715d82f18ba850cad724863832e43d45bbd4ccffd
924ffa1189b7695a7d6c610fb766ff7ea30a26cd69924f9f140edac5f609a304
82826372656672726566732f68656164732f70722f31323334836565706f6368
72726566732f68656164732f70722f31323334010558203d4017c3e843895a92
b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c0658403fda3b61fb04
2cf3fe81e027fb7968fef6f8e40fb59e7ccb98117c97392ba0bbd5aa8e92a5fa
f958af1cb6f61f739b5c6cec2e194e644058ea2d4f8989ac700c
```

A verifier MUST accept this token with `k1` configured as an issuer key,
MUST reject it once the clock passes 1 760 003 600, and MUST reject a commit
under it to any ref other than `refs/heads/pr/1234` or at writer epoch
greater than 1 ([`../22-authentication-and-authorization.md`](../22-authentication-and-authorization.md)
AUTH-14, AUTH-18).

## Reproduction

The vectors were produced with the reference BLAKE3 and Ed25519
implementations and a hand-written canonical CBOR encoder. A conformance
suite regenerates them from the same inputs; a mismatch in any byte is a
failure of `gate:golden-vectors`.
