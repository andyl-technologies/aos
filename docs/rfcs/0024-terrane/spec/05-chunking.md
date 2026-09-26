# 05 — Chunking and compression

This file defines how file bytes are cut into chunks, how chunks are
compressed at rest and on the wire, and what a receiver checks before it
admits a chunk. Chunk boundaries determine deduplication; they are part of a
store's profile and fixed for its lifetime.

## Overview

Chunks are cut by content-defined chunking so that the same run of bytes
produces the same chunks wherever it appears. The algorithm is FastCDC with
a gear table derived from a seed. Each chunk is compressed independently
with zstd, optionally against a trained dictionary chosen by the file's
content class, so that any chunk can be fetched, verified, and decompressed
alone and so that a sequence of chunks can be streamed as a single zstd
stream without recompression.

## Chunking parameters

- **[CDC-1]** The chunker is FastCDC (Xia et al., USENIX ATC 2016) with
  normalized chunking level 2, using a 256-entry gear table of 64-bit values.
  The gear table MUST be derived deterministically from the profile's seed by
  the procedure in [`reference/golden-vectors.md`](reference/golden-vectors.md)
  §gear-table so that every implementation of a profile cuts identical
  boundaries. *Gate:* `gate:cdc-boundaries`.
- **[CDC-2]** The `terrane-v1` profile's chunking parameters are:

  | Parameter | Value |
  | --- | --- |
  | minimum chunk size | 256 KiB (262 144 bytes) |
  | target (average) chunk size | 1 MiB (1 048 576 bytes) |
  | maximum chunk size | 4 MiB (4 194 304 bytes) |
  | rolling window | 48 bytes |
  | normalization level | 2 |
  | seed | the 32-byte value in the profile record |

- **[CDC-3]** Chunking parameters are part of the store profile and MUST NOT
  change while any chunk exists in the store. Changing them is a migration
  that produces new chunk identities ([`33-migrations.md`](33-migrations.md)).
  Compression level and dictionary set are not part of the profile and MAY
  change at any time, because they do not affect identity (OBJ-3).
- **[CDC-4]** A boundary MUST be placed at end of file. The final chunk of an
  object MAY be shorter than the minimum. No other chunk may be shorter than
  the minimum or longer than the maximum.
- **[CDC-5]** An empty object MUST be represented as exactly one zero-length
  chunk. Its identity is the digest of the empty byte string under the
  chunk domain, and it is admissible to any store without upload.
- **[CDC-6]** The chunker MUST be a pure function of the profile and the
  input bytes. It MUST NOT depend on file names, positions within a tree,
  or previous files. *Gate:* `gate:cdc-boundaries`.

## Compression

Each chunk is stored and transferred as a codec byte followed by the
encoded body.

| Codec | Value | Body |
| --- | --- | --- |
| raw | `0x00` | the plaintext |
| zstd | `0x01` | one zstd frame containing the plaintext |
| zstd with dictionary | `0x02` | a 32-byte dictionary identity followed by one zstd frame compressed against that dictionary |

- **[CDC-7]** The body of codec `0x01` and `0x02` MUST be exactly one zstd
  frame (RFC 8878) whose decompressed content is the chunk plaintext. The
  frame MUST include the content size in its header and MUST NOT use a
  skippable frame or a frame with unknown content size. *Gate:*
  `gate:chunk-codec`.
- **[CDC-8]** A writer SHOULD use codec `0x00` when compression would not
  reduce the body below 97 % of the plaintext length. A reader MUST accept
  any codec for any chunk; the codec is not part of identity.
- **[CDC-9]** The dictionary identity in codec `0x02` MUST be the identity
  of the dictionary bytes under the `terrane-attr-v1` domain with the
  attribute name `zstd-dictionary`, stored as a derived-data record
  ([`10-derived-data.md`](10-derived-data.md)) so that any tier can fetch
  the dictionary through the ordinary content path. A reader that lacks the
  dictionary fetches it before decoding; a reader MUST NOT guess.
- **[CDC-10]** Dictionaries are trained per content class and selected by
  the object's classification attribute ([`10-derived-data.md`](10-derived-data.md),
  [`31-routing-rulesets.md`](31-routing-rulesets.md)). A writer MAY select a
  dictionary for any chunk; the choice affects only the stored body.
  Registered content classes and their default dictionaries are listed in
  [`reference/property-registry.md`](reference/property-registry.md).
- **[CDC-11]** For codecs `0x01` and `0x02` with the same dictionary, the
  concatenation of the bodies of an object's chunks in manifest order MUST
  be a valid zstd stream that decompresses to the object's plaintext. A
  surface MAY serve a compressed whole-object response by concatenating
  stored bodies without decompression. For a mixed-codec object a surface
  MUST recompress or serve plaintext. *Gate:* `gate:zstd-concat`.

## Validation on admission

A chunk is admitted to a store or a cache only after every check below has
passed. The checks are identical whether the chunk arrives from an
untrusted uploader, a peer, a bucket, or a local disk; the source of a chunk
is never trusted ([`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md)
G-7).

- **[CDC-12]** The receiver MUST decompress the body into a buffer bounded
  by the declared plaintext length and MUST reject the chunk if
  decompression produces more bytes than declared, fewer bytes than
  declared, or fails. The declared length MUST NOT exceed the profile's
  maximum chunk size. *Gate:* `gate:chunk-bomb-cap`.
- **[CDC-13]** The receiver MUST reject a compressed body whose length
  exceeds the declared plaintext length by more than the zstd frame
  overhead bound of 128 bytes plus 1 % of the plaintext length, so that an
  attacker cannot store arbitrary bytes under the guise of a poorly
  compressible chunk.
- **[CDC-14]** The receiver MUST compute the identity of the decompressed
  plaintext and MUST reject the chunk if it differs from the identity under
  which the chunk was offered. *Gate:* `gate:verify-before-admit`.
- **[CDC-15]** The receiver MUST reject a chunk whose plaintext length is
  below the minimum or above the maximum unless the chunk is offered as the
  final chunk of an object, in which case only the maximum applies.
- **[CDC-16]** For a chunk that is not the final chunk of its object, the
  receiver MUST run the profile's chunker over the plaintext and verify
  that the first boundary it finds is at end of chunk and that no earlier
  boundary exists past the minimum size. Because the rolling window is
  shorter than the minimum chunk size, this check is exact using only the
  chunk's own bytes. A chunk that fails is rejected as malformed even if its
  identity is correct, so that an uploader cannot pollute the deduplication
  space with boundaries no honest chunker would produce. *Gate:*
  `gate:cdc-boundaries`.
- **[CDC-17]** When an object is committed, the receiver MUST verify that
  the manifest's chunk count does not exceed `ceil(size / minimum) + 1` and
  that every chunk but the last satisfies CDC-15 and CDC-16. Chunks that
  already exist in the store and were admitted under these rules need not
  be re-checked.
- **[CDC-18]** A receiver MUST NOT admit any bytes of a chunk to durable
  storage or to a cache readable by others before CDC-12 through CDC-16
  have passed. Partial or unverified bytes live only in private staging and
  are discarded on failure ([`14-host-tier.md`](14-host-tier.md)).

## Chunks and objects

- **[CDC-19]** An object's manifest lists chunks in file order. The chunker
  output for a file, in order, is the only valid chunk list for that file
  under a profile; a manifest with the same chunks in another order or with
  different boundaries describes a different object and MUST NOT be
  presented as the same file.
- **[CDC-20]** Files whose length is at most the minimum chunk size are a
  single chunk and are referenced inline from tree entries without a
  manifest (OBJ-16).

## Interactions

- [`04-content-model.md`](04-content-model.md) defines chunk identity and
  the manifest that lists chunks.
- [`10-derived-data.md`](10-derived-data.md) stores dictionaries and
  classification attributes.
- [`12-pack-format.md`](12-pack-format.md) stores chunk bodies with their
  codec byte.
- [`14-host-tier.md`](14-host-tier.md) applies the admission checks at the
  host tier.
- [`21-bandwidth.md`](21-bandwidth.md) uses dictionaries and wire deltas.
- [`30-surface-protocols.md`](30-surface-protocols.md) uses CDC-11 to stream
  compressed whole objects.
- [`reference/golden-vectors.md`](reference/golden-vectors.md) fixes the gear
  table derivation and boundary vectors.

## Informative: why these parameters

A 1 MiB average chunk keeps per-object metadata small (about 40 bytes per
chunk in a manifest) and makes ranged reads from a bucket efficient, while
the 256 KiB minimum keeps small-file overhead from dominating and lets the
boundary check in CDC-16 be exact. The 4 MiB maximum bounds the memory a
receiver needs to verify one chunk. Larger averages would improve bucket
throughput at the cost of deduplication granularity on large files that
change in the middle; smaller averages would inflate manifests and index
size. The parameters are a profile value precisely so that a store built
for a different workload can choose differently without changing any code.
