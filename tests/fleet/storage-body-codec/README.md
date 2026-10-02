# Storage body observation codec

This source-built fixture classifies exact captured application bodies using
the production Copy and stored OCI projection decoders. Distribution controls
use the shared ingress observation decoder, exact private phases and closed
DTOs. It authenticates no MAC and grants no current permission.

Build through the AOS development environment, then run the binary directly:

```sh
nix develop -c cargo build --manifest-path tests/fleet/storage-body-codec/Cargo.toml --locked
<target>/debug/aos-storage-body-codec <private-selection.json>
```

The selection is owner-private JSON with `version: 1`, `sourceDigest`,
`deploymentId` and `cases`. Each case names `requestId`, `method`,
`pathAndQuery`, `phase` (or null), `status`, `responseContentType`,
`responseContentEncoding`, `originalRequest`, `receivedRequest`,
`receivedReply`, `originalIngress` and `receivedIngress`. File references are
`{ "file": "...", "sha256": "<64 lowercase hex>", "byteSize": "<decimal>" }`.
Ingress references contain the exact compact header bytes and are required for
Distribution. They are absent for the independent storage controls. No token,
compact header, physical path or payload is emitted.

Every selected file must be an owner-private regular file with its exact
commitment. Symlinks, changed files, mismatched originals, unknown fields,
unsupported routes/phases/statuses, encodings and truncated replies refuse the
whole selection. The limits remain 8 MiB per body, 4,096 cases and 512 MiB of
selected file bytes, including independent original copies. A refusal returns
exit 1 with a fixed error; it never supplies a zero result.

The output is an array of closed codec rows. Original object bytes, encoded
control bodies, decoded selected data and semantic OCI projection sizes remain
distinct. Stored document descriptor sizes and Copy provider progress are not
Native transport bytes. Manifest completion must be exactly the two bytes
`{}`; the original manifest is not completion metadata.

The selected helper source/lock/executable must be independently retained and
bound to the final deployed runtime source. Its `codecSourceSha256` commits the
compiled fixture source files; the separate source proof must bind the actual
shared crate. A supplied `sourceDigest` is a selection coordinate, not runtime
self-attestation. Historical Observer007 and its receipts remain unchanged.

The fleet join additionally needs complete independent original/received
captures, actual post-authentication Native consumption events or equivalent
accepted ingress observations, current SQL actor/profile/purpose evidence and
fully attributed provider observations. Missing evidence keeps
`nativeBulkBytes` null. JSON shape, successful HTTP status and this codec's
output alone establish neither authentication nor Native bulk zero. Additional
Distribution/bootstrap routes and embedded descriptor `data` object bodies
remain unsupported until explicitly reviewed.
