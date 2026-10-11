# Internal queued verification observations

This confined `do-e2e` observer records the actual Worker-local
`VerifyClosedStage` work. It creates no Native Stage HTTP execution and supplies
no queue MAC, current authorization, provider dispatch or publication authority.
The ordinary build has no observer configuration or logging.

## Initial selection

Before the first Worker observation, install the closed UTF-8
`HUB_DIRECT_VERIFICATION_FAULT_OBSERVER` value:

```json
{"version":1,"stagingPrefix":"managed/.aos-direct-qualification/run/.aos-direct-upload","expectedSourceSha256":"<actual SHA-256>","expectedSourceBytes":"<actual decimal size>"}
```

The prefix is the actual installed typed External Stage staging prefix, not the
registry placement prefix. It must contain `.aos-direct-qualification` and end
with `/.aos-direct-upload`. The independently known source is 1 through 65,536
bytes. A different prefix, SHA, size or operation does not select an observation.
The selection is a fixture ceiling and grants no provider permission.

## Actual records

Private Worker console lines begin with
`direct_verification_fault_observation ` followed by canonical closed JSON.
Keep each exact JSON suffix in a private file; do not normalize or reconstruct
it. Retain the whole source-pinned Worker process/log lifetime and every matching
attempt. Each record is at most 65,536 bytes. Overflow, malformed records,
duplicate identifiers or an omitted attempt prevent complete evidence.

A fresh 32-character lowerhex `attemptId` correlates these records:

- `started`: `projection` contains the actual canonical queue-job SHA and a
  closed projection of its Core admission, Complete, placement and closed result,
  plus the actual work. The wasm-only queue wire schema is not copied to the
  host helper.
- `prepared`: `prepared` contains the identical projection, actual physical
  journal Turn/Receipt, retained floor and direct permission expiry, bucket,
  full key, URL and required headers. Existing same-journal closure checks and
  strong conditional signing are reused. Preparation precedes the final fresh
  clock/lease/floor checks. It is not a dispatch receipt.
- `terminal`: version, attemptId, status (`positive`, `error` or `dropped`) and
  the actual result only when positive. A dropped future remains incomplete.
- `incomplete`: the record cannot establish complete observation.

Optional closure versions come only from the retained actual acknowledged
provider header. A versionless receipt remains versionless; neither a guard
incarnation nor a Workers R2 version is an S3 version ID.

## Typed host consumer

Select the lib-test executable built from the same accepted do-e2e source with
`cargo test --release --frozen --offline --no-run -p aos-hub-worker --lib --features do-e2e`.
Run exactly its ignored selector:

```text
AOS_PROVIDER_HOLD_STAGE_OBSERVATION_INPUT=/private/input.json
<selected Worker test ELF> external_object::stage::tests::observation::actual_verification_hold_observation --exact --ignored --nocapture
```

The input file and each record are owner-private regular files. Input is closed:

```json
{"version":1,"records":[{"path":"/private/record.json","sha256":"<actual file SHA>","byteSize":"<actual decimal bytes>"}],"output":"/private/new-output.json"}
```

There are 1 through 32 records, each at most 65,536 bytes; input is at most
16,384 bytes. The output is created exclusively with mode 0600. Its closed
fields are `version`, `scope`, `attempts`, `currentAuthorization`,
`providerDispatch` and `nativeBulkBytes`. Scope is
`unverified_internal_verification_projection`; the last three fields are null.
Each attempt retains `projection`, optional `prepared`, optional `terminal` and
`completeObservation`. That last field means only that preparation and a
non-dropped terminal were captured. It is not a fault-test PASS.

## Independent required joins

Join the actual Native admission/Complete authentication and current SQL tuple,
actual retained queue job SHA, Worker source/script/process/capture custody,
current binding/profile/role and actual physical journal closure. Join the
prepared signed target/If-Match/optional version to the listener's real upstream
GET, actual 200/ETag/source bytes/hash and held downstream response. The fresh
work cutoff must be within the fixture ceiling and its actual terminal must be
observed. Missing or incompatible joins stay unresolved.

Retain the complete outer normal publisher inventory, including the genuine
multipart uploads and positive closure before verification. The no-write and
no-publication assertion applies to this exact failed verification-operation
subwindow, anchored to its real work/job/session and provider request. Earlier
uploads are never erased or classified as verification effects. A prepared
record without an actual GET cannot satisfy a timeout case. A retained positive
replay without a new GET cannot substitute for the first held response.
