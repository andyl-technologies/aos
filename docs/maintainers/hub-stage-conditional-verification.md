# Conditional verification of a positively closed external stage

Queued verification selects the same positive closure retained by its permanent
physical-key journal. Before provider dispatch, the journal checks the complete
verification turn against the pending read, original context, closure operation
and receipt digest, frozen multipart manifest, provider UploadId, and current
guard incarnation. The executor checks that protected projection again before
building the request. A caller cannot substitute an ETag or choose another
closure in the compact verification request.

The full-object S3 GET signs the original strong `If-Match` header. It includes
`versionId` only when the actual positively acknowledged closure response
supplied a bounded, non-null `x-amz-version-id`. Before consuming object bytes,
verification requires a positive response with the same strong ETag and, for
an actually versioned closure, the same provider version. The existing complete
size, full SHA-256, and ordered part integrity checks remain required.

## Retained wire compatibility

The private stage `Receipt` gains an optional `provider_version`. Absence and a
literal null provider response retain `None`; serialization omits that member.
Historical receipts therefore retain their exact canonical bytes, receipt
digests, and control signatures. New versioned receipts bind the actual version
into their receipt digest. The public `ExternalStageOutcome` and
`ExternalStageResult` shapes do not change.

Only positive `Closed` or `EmptyClosed` receipts may retain a provider version.
The executor reads the header from the actual acknowledged Complete or empty
PUT response before consuming its metadata. Guard stamps, ETags, key names and
content hashes never manufacture an S3 version. Newly allocated empty-object
effects remain refused by the existing provider qualification gate.

The private `Dispatch` reply gains the original positive `closed` receipt for
verification. It comes from the authenticated addressed journal operation and
the same durable session reference as the pending read. An absent closure on a
verification dispatch refuses. Other operations refuse an unexpected closure.
Mixed old/new executors are not qualified: an old decoder can refuse the new
member, while old terminal receipts without a version remain readable.

## Versionless backends and pending outcomes

A closure without a retained S3 version receives a strong-condition read of the
current object. This does not establish historical version addressability or
allow translating a Workers R2 version into S3 `versionId`. An actual replaced
object with a different ETag is refused; a successful condition still requires
the original full SHA and size. A provider that ignores the condition and
returns a changed ETag or version is refused before body consumption.

The returned native BYOB reader owns cancellation before any fallible status or
header checks. A refused status, missing ETag or changed incarnation drops that
same unpolled reader and invokes native cancellation. Successful selection
transfers the existing owner into the full-object verifier. Cancellation invocation
does not establish remote drain, reclaim a pending mutation or settle its outcome.

No new upload or publication authority is created. Original logical deadlines,
fresh read leases, current floors, the final synchronous dispatch check, and
unknown mutation fences remain in force. A failed conditional read leaves its
original verification pending; it does not clear a mutation fence or create a
new provider UploadId. Native continues to receive compact metadata rather than
the provider object body.

## Verification scope

Focused source tests cover historical receipt bytes and digests, same-session
closure selection and restart, substituted context/turn/incarnation/reference,
actual optional-version parsing, changed response ETag/version, and signed
header/query commitments. These tests do not establish provider conditional-read
conformance, actual queue delivery, source-replacement fault qualification,
Hosted acceptance, or the final deployment tuple. Those remain separate runtime
measurements with actual provider and publication observations.
