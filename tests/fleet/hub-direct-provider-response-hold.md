# Actual Garage response hold

This local fixture owns one bounded provider response between the initial fleet
S3 TLS proxy and Garage. It does not create an object, authenticate a caller,
change a placement, grant a capability, retry a request, or establish a timeout
qualification by itself. The existing Map-based timeout adapter is separate.

## Initial installation

Use the selected source-built Node executable and this selected listener:

```text
NODE _hub-direct-provider-response-hold.mjs --config PRIVATE_CONFIG
```

The closed, owner-private mode `0600` configuration is
`{"version":1,"root":"/absolute/private/fixture/root"}`. The root must already
be an owner-private mode `0700` directory without a symlink. The CLI fixes the
listener at `127.0.0.1:3902` and its only upstream at `127.0.0.1:3900`.
Garage's RPC port `3901` remains separate. In the initial S3 Nginx configuration,
the existing TLS `443` location forwards to `3902`, preserving the original
Host, raw URI and signed request headers. The listener streams unselected
traffic to Garage, including normal writes; the fault path itself performs no
write. No configuration rewrite follows source/profile observations.

Require `ready.json` after the HTTP listener and private `control.sock` have
both bound. Its closed fields are `version`, `scope`, `pid`, `startTicks`,
`ownerUid`, `configurationSha256`, `executableSha256`, `commandLine`,
`environment`, `listenAddress`, `upstreamAddress`, `listenerSourceSha256`,
`controlSocket`, and `bodyBound`. Scope is `garage_response_hold_listener` and
bodyBound is the decimal string `65536`. Command and environment are private
file references with `path`, `sha256`, and decimal-string `byteSize`. The caller
must independently compare the actual launch lifetime, initial configuration,
executable and selected source before sending controls. Tests use ephemeral
loopback ports through the exported factory; production CLI offers no port flag.

## First verification response

The selected timeout lane uses the first genuine `VerifyClosedStage` conditional
GET. A prior successful verification can be cached and therefore cannot be used
as a reliable calibration producer. Do not predict a session or poll its journal
before a tiny queued verification finishes.

Send one owner-private closed control before starting the normal publisher:

```json
{"version":1,"kind":"arm_first_response","selection":{"version":1,"targetPrefix":"/ACTUAL_BUCKET/ACTUAL_RESERVED_PREFIX/.aos-direct-upload/","host":"s3.fleet.test"},"expectedSourceBodySha256":"ACTUAL_SOURCE_SHA256","expectedSourceBodyBytes":"123","selectionContextSha256":"ACTUAL_SELECTION_CONTEXT_SHA256","holdUntilUnixMillis":0}
```

Derive `targetPrefix` from the actual installed `HUB_EXTERNAL_STAGE`
`domains[].staging_prefix` or exported `bootstrap.staging_prefix` and the admitted
binding's actual bucket, using path-style `/<bucket>/<staging_prefix>/`. This is
not the registry placement prefix. It must contain the reserved
`.aos-direct-qualification` segment and end in `/.aos-direct-upload/`; the caller
independently establishes the fresh namespace and initial installed selection.
The listener rejects query/percent escapes, dot segments and an unconfined prefix.
The known source hash and canonical decimal byte count `1..65536` describe real
signed publication input selected before dispatch, not a future Native original.
The context commitment describes only this selection. The UTC fixture ceiling
must be in the next 35 seconds; it grants no production authority or deadline.

At most eight sequential candidate responses are observed, each with at most
64 KiB buffered body and no concurrent candidate buffer. Ordinary concurrent
reads and later reads forward normally. A candidate must be a GET under the
exact prefix with no Range, signed Host and strong If-Match. Its raw signed URI
and headers are retained and forwarded unchanged. A nonmatching signature form,
status, ETag, Content-Length, or source hash forwards the real response unchanged.
Only a complete real upstream `200` with matching strong ETag, exact known
Content-Length and full source hash becomes the single held tuple. No headers,
body or synthetic `504` are sent for that tuple. Optional S3 version headers are
retained as observed; absence remains null.

State adds `firstResponse`, the actual held receipt reference or null, separately
from `calibrated`. Events add `first_response_armed`, `first_request_received`,
`first_upstream_complete`, and `first_response_not_selected`. Request and response
files retain the exact derived key and complete upstream facts. The new actual
session, placement and physical key must be derived from the captured
`ExternalStageRequest` context afterward. The Core staging key is
`<staging_prefix>/<sha256(session_id UTF8)>/<placement_id>/payload`.
Independently join that exact new request, same-session retained closure,
current SQL/profile/MAC, actual conditional GET and terminal to the held tuple.
Its actual cutoff must be no later than the fixture ceiling. Missing or failed
joins, exhaustion without a match and a generic transport error remain unknown.
No cached second verification or supplied permission flag can replace this join.

## Optional prior-response calibration

This older observation mode remains available for separately scoped diagnostics.
It is not the selected first-verification producer.


Send one closed JSON message to the owner-private Unix socket and half-close
the write side. Whole controls are bounded to 16 KiB, duplicate fields and
unknown fields refuse, and socket mode is `0600`.

```json
{"version":1,"kind":"calibrate","selection":{"version":1,"target":"/actual-bucket/actual-key","host":"s3.fleet.test","range":null}}
```

The target selects the exact raw object path and non-signing query from actual
placement/provider selection. The closed SigV4 signing query fields are removed
only for selection: X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, X-Amz-Expires,
X-Amz-SignedHeaders, X-Amz-Signature and optional X-Amz-Security-Token. versionId
and every unknown query component remain exact. The entire raw signed URI is
forwarded unchanged and retained privately for each invocation. An actual range uses `"bytes=START-END"`. Then execute one
normal production conditional read with a real protected original. A public NAR
GET that signs only Host and lacks If-Match does not satisfy this contract; a
version-required read cannot substitute a version on Garage. The actual called
producer and independently authenticated original are mandatory integration
dependencies, not supplied by this listener. The selected GET must
contain a strong If-Match and source-supported SigV4 header or presigned-query
fields whose SignedHeaders includes Host and If-Match (and Range when selected).
Header and query signatures cannot ambiguously coexist; the bounded production
query signer permits at most thirty seconds. The listener forwards those exact fields to Garage.
It requires a real upstream `200` or `206`, matching strong ETag, complete body
framing and a nonempty body of at most 64 KiB before forwarding that response.
The backend performs authentication. The caller must separately retain the
actual private bucket/credential policy, current SQL and authenticated original;
HTTP status or signature syntax alone is not authorization proof.

```json
{"version":1,"kind":"state"}
```

State has fields `version`, `calibrated`, `firstResponse`, `armed`, `attempted`,
`observationsComplete`, and `scope` (`observation_only_no_authorization`).
`calibrated` is null or the actual private receipt reference. The receipt has
`version`, `scope`, `identity`, `response`, `requestFile`, `headersFile`,
`bodyFile`, `upstreamComplete`, and `authenticationScope`. Identity is
`{method,target,host,ifMatch,range,signingMode,signingCredentialSha256}`. Response is
`{status,etag,versionId,byteSize,sha256,contentRange}`. Absent actual S3 version
headers remain null; a query or R2 version is never substituted. Range bytes
and their hash describe the selected partial body, independently of the retained
whole-object identity. Private request/response headers include credentials;
retain them privately and publish only reviewed commitments.

```json
{"version":1,"kind":"arm","calibrationSha256":"ACTUAL_RECEIPT_SHA256","expectedSourceBodySha256":"ACTUAL_SELECTED_SOURCE_BYTES_SHA256","calibrationContextSha256":"ACTUAL_CALIBRATION_CONTEXT_SHA256","holdUntilUnixMillis":0}
```

Replace the timestamp with a real future UTC millisecond ceiling no more than
35 seconds away. Calibration and expected source hashes must match the actual
retained response. The context hash describes the calibration context only;
it is not the future read's original or an authority checked by the listener.
The control replies `selected`, `armed`, or `refused`. One calibration and one
arm are allowed per listener lifetime. Do not restart to retry a failed case.

Execute one fresh normal production read. Its exact target, Host, If-Match and
Range must match calibration. Its new signature/date fields are retained separately. Signing mode and the
credential commitment must remain equal; no new provider principal is inferred.
After a genuine upstream complete response with the same status, ETag, actual
optional version, size, hash and Content-Range, the listener withholds all
downstream response headers and body. It sends no synthetic timeout status.
The fixture ceiling or actual downstream close terminates custody. Those events
do not prove remote drain, Worker cancellation, or physical settlement.

## Required independent joins

The fresh read creates a new Native original. The caller must independently join
that exact original, MAC/current context, unchanged SQL, provider selection and
raw Worker terminal to this fresh received provider request and response. Require
its actual valid cutoff to be no later than the hold ceiling; neither a supplied
ceiling nor the older calibration plan is a production deadline. Missing original,
late arm, wrong request, incomplete observations or unknown terminal remain
unresolved. The complete outer publication inventory must retain normal earlier uploads,
provider PUTs and closure, including their actual bytes and outcomes. The failure
assertion applies to the typed verification operation subwindow only: anchor it
to the actual new `VerifyClosedStage` original, same-session closure, conditional
provider GET and terminal. That failed verification operation must not issue a
provider write or publish. No row may be dropped from the outer inventory to
make this narrower assertion pass. This listener never concludes Native bulk bytes or a zero-SDK result.

Private event files distinguish `calibration_request_received`,
`calibration_upstream_complete`, `calibration_forwarded`, `armed`,
`hold_request_received`, `hold_upstream_complete`, `response_held`,
`downstream_closed`, `hold_deadline_reached`, and `selected_refused`.
Every event has `version`, `kind`, `sequence`, and actual `unixMillis`.
`downstream_closed.closeCause` distinguishes `downstream` from `fixture_ceiling`.
Held offered bytes are listener-only `0`, with `remoteDrain:null`.
At 32 events, `observation-incomplete.json` marks the bound; state becomes
incomplete and cannot authorize a new arm. Whole-window provider records still
include every ordinary calibration/fault/other invocation, not just these events.

Focused source-built Node tests exercise actual local sockets, forwarding,
calibration, held headers/body, incarnation changes, malformed arms, bounded or
truncated responses, closure and unchanged ordinary traffic. Their backend is a
local transport fixture, not Garage authentication, actual Worker timeout, Fleet,
Hosted, or resource qualification. Actual selected-tuple execution remains pending.
