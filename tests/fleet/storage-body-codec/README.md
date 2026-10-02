# Storage body observation codec

This source-built fixture classifies exact captured application bodies using
the production Copy, External OCI and stored OCI projection decoders. Distribution controls
use the shared ingress observation decoder, exact private phases and closed
DTOs. It authenticates no MAC and grants no current permission.

The Managed GC allowlist is `ListPage`, `Head`, `HashOciRange` and
`DeleteIfMatches` on the exact storage-work route. It uses the Native
`test-support` facade for the unchanged shared result correlation/budget checks,
and the shared observation-shape validator. Debug assertions must remain
enabled; stripping debug sections does not change those semantics. No synthetic
historical clock is passed. Probe, raw range, content and other operations refuse.

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
Distribution routes outside the explicit phase allowlist and embedded descriptor
`data` object bodies remain unsupported. Empty upload creation, status,
cancellation and final completion use the actual shared query parsers. The
`authorize-final` reply is the closed two-boolean routing hint, bounded to 1 KiB;
it does not establish IAM, a selected writer or successful completion.

The separate Managed collector is `_hub-managed-storage-window.py`. Its
`begin_managed_storage_window`/`finish_managed_storage_window` callbacks pin the
four actual Native, Worker and proxy processes before and after fixed private
file windows. Plain Native logs have no event timestamp: collection brackets
are retained separately, and their parsed transport clock stays null. The
per-capture `classify_managed_storage_capture` callback executes an independently
selected current helper against the original and consumed request/reply files,
then reopens their exact commitments before returning typed plan/result data.
Its local decoder receipt does not authenticate a handler or validate action
SQL. Those joins, installed purpose and provider observations remain required.

The Managed Worker proxy independently retains its original requests to Native
on port 4644, alongside Native's received requests. Both exact body pairs and
compact ingress pairs must match before selected Distribution decoding runs.
Every unsupported, unrelated, missing or ambiguous row remains accounted for;
successful shape decoding alone leaves `nativeBulkBytes` null. The proxy's
completion UTC and private file collection brackets are distinct observations.

## Managed terminal cleanup metadata

The exact `/_internal/storage/managed-oci-cleanup/v1` positive metadata class
uses the production 16 KiB canonical request/reply parser and full intrinsic
original/nonce/key/size/opaque-R2-version/strong-ETag correlation. Selected
issuer source must match the current observation source. Historical decoding
does not check a MAC, current clock, SQL claim, Delete capability or provider
effect and grants no cleanup permission. Empty, partial, expanded, substituted
or unsupported replies refuse. The listener's fully consumed authenticated
upstream response must never substitute for the Native application's actually
consumed downstream reply. Lost/reset calls remain incomplete until independent
actual body/consumption evidence exists. A codec metadata partition alone does
not establish whole-window Native bulk bytes of zero.
