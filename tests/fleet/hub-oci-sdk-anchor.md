# Local OCI SDK anchor fixture

This fixture makes one bounded, retained anchor in a dedicated local Miniflare
R2 namespace. The actual `getR2Bucket` attachment performs a conditional Put
and an ETag-conditional full read. It does not install acceptance, sign evidence,
qualify generic Managed Direct or Hosted R2, or run the business OCI workflow.
The existing guard observation and External artifact installer remain separate.

## Inputs and installation joins

Start from an independently reviewed source-built Node/Miniflare/workerd closure
and an owner-private, create-new persistence root. Select a new namespace named
`oci-sdk-qualification-<32 lowercase hex>` for `REGISTRY_BUCKET`; the selected
worker name and normalized namespace must have no aliases or remote bindings.
Use the existing runner configuration with these additional selections:

```json
{
  "r2Buckets": {"REGISTRY_BUCKET": "oci-sdk-qualification-<32hex>"},
  "ociSdkAnchorEnabled": true,
  "ociSdkNamespaceObservation": {
    "sourceStorePath": "<selected immutable Worker source>",
    "wasmPath": "<installed distribution>/index.wasm",
    "workerdPath": "<selected source-built executable>"
  }
}
```

These are additions to a complete reviewed runner configuration, not a complete
Worker configuration. That configuration also selects the real module, worker
name, HTTPS certificate/key, owner-private control socket and persistence root.
`ociSdkAnchorEnabled` is stripped before Miniflare option parsing. It authorizes
only this fixture command after a live dedicated namespace observation; it is
not a runtime acceptance property.

The namespace observer pins the installed Miniflare `5.20260801.0-alpha` module,
R2 worker and object-entry worker bytes. Its actual schema/plugin normalizes the
binding and connects it to the live `R2BucketObject` ID and persistence key.
Use `_hub-oci-sdk-namespace.py` to capture and independently check the running
socket peer PID/UID, runner and child start ticks, parentage, selected executable,
configuration, module/shim/Wasm hashes, source and script identity. Preserve its
raw private receipt and the independently authenticated Worker identity join.
A configuration string or a build-derived digest alone is insufficient.

The anchor client imports the adjacent `_hub-oci-sdk-namespace.py`; include that
exact published dependency with the anchor client and runner. Install all files
through explicit immutable fixture inputs, without an undeclared build-directory
mount. Retain source/package NAR hashes, tool executables and dependency hashes
beside the process/configuration observations.

Previously built runner tools may be reused with their actual recorded identities.
A retained older Wasm can support only an explicitly labeled prerequisite
experiment. Final OCI acceptance and workflow evidence require the newly built
Native and Worker artifacts containing the separate OCI-only purpose, one exact
selected immutable runtime source, and the actual installed console/CLI closure.
No older artifact may be relabeled as the new runtime.

## Authenticated source join before acceptance

The existing qualification driver provides a source-only `--phase clock`.
Supply the exact selected build source/script and public origin as its private
identity input, the distinct private conformance key, a fresh 64-hex run ID and
a new empty output directory:

```text
<AOS Node> aos-hub-direct-qualification.mjs --phase clock
  --origin <actual installed HTTPS origin>
  --control-key-file <private conformance key>
  --identity-file <selected build identity and publicOrigin>
  --run-id <fresh64hex> --clock-uncertainty-seconds <installed decimal policy>
  --output-dir <new private clock capture directory>
```

The actual protected Clock branch returns the compiled source/script before
acceptance lookup or provider operations. The driver verifies its separate
reply MAC, exact request SHA/nonce, closed Clock shape, source/script and selected
uncertainty; it retains the actual request and signed reply. Only then does it
write `source-identity.json` for the namespace reader. This source/clock
observation grants no Managed Direct or OCI acceptance. The phase issues no
Start, Begin, Enqueue, Status or provider request. Later SDK effects still
require the independent namespace/configuration/process joins.

## Retained original and one-shot command

The control request has exactly four fields:

```json
{
  "version": 1,
  "kind": "oci-sdk-anchor-create",
  "originalBase64": "<exact retained original bytes>",
  "originalSha256": "<SHA256 of those bytes>"
}
```

The original contains exactly `version`, `runId`, `issuedAt`, `expiresAt`,
`namespaceObservationBase64`, `namespaceObservationSha256`, `payloadBase64`,
`payloadSha256` and `payloadByteSize`. `runId` is fresh random lowercase 32-hex;
UTC seconds and payload size are canonical decimal strings. The command permits
1–1024 payload bytes and at most 30 seconds between issue and expiry. The client
prepares 256 random bytes. Embedded bytes have canonical base64 and exact hashes. The original is UTF-8
JSON with sorted keys, compact separators and one final newline; duplicate or
noncanonical originals refuse before SDK dispatch.

The client first fsyncs create-new private `original.json` and `request.json`.
Before socket dispatch it independently checks the selected live Node lifetime
and actual socket `SO_PEERCRED`, then retains a permanent `dispatch-intent.json`.
A second dispatch refuses before send even after a connection loss. The runner
freshly observes the namespace and compares every retained field except the
observation timestamp. It fsyncs a separate create-new run original before any
SDK mutation; an existing run directory always refuses before another SDK call.

The derived object key is exactly:

```text
.aos-oci-sdk-qualification/<original runId>/anchor
```

The selected SDK Put uses `onlyIf: {etagDoesNotMatch: "*"}` and the original
SHA256. The pinned R2 implementation permits this condition for an absent object
and refuses an existing incarnation. The subsequent SDK Get uses
`onlyIf: {etagMatches: <unquoted actual positive ETag>}`. The conditional
value removes only the quotes from the already validated canonical HTTP ETag;
the retained object identity keeps that quoted HTTP ETag. The returned version, strong
ETag, key and size must match the Put; the consumed complete body must match the
original size and full SHA256. The command checks real UTC before dispatch and
after each awaited SDK/stream operation; backward or expired clocks refuse a
positive outcome. No helper clock offset or invented permission time is used.

The bounded positive receipt contains exactly:

```json
{
  "version": 1,
  "status": "observed",
  "anchor": {
    "object": {
      "key": ".aos-oci-sdk-qualification/<32hex>/anchor",
      "provider_version": "<actual SDK version>",
      "etag": "\"<actual strong SDK ETag>\"",
      "size": 256
    },
    "sha256": "<full actual body SHA256>"
  },
  "runId": "<original 32hex>",
  "originalSha256": "<original bytes SHA256>",
  "namespaceObservationSha256": "<private namespace report SHA256>",
  "completedAt": "<actual UTC milliseconds>",
  "sdkInvocations": {"put": 1, "get": 1}
}
```

`provider_version` and numeric `size` use the actual core
`StorageObjectIdentity` spelling. This pinned emulator returns a random 32-hex
version and a quoted 32-hex MD5 ETag. SDK invocation counts describe local calls;
they do not establish server settlement after a lost reply. Conditional create
refusal returns `refused`; any incomplete or failed possible dispatch returns
`unknown` without an anchor. The runner retains the receipt in its private
`oci-sdk-anchor-journal/<runId>` directory.

Nonpositive outcomes also retain a private `diagnostic.json` sidecar with
exactly `version: 1`, `stage`, and `code`. Fixed stage names are
`pre_dispatch`, `select_sdk_bucket`, `conditional_create`, `created_identity`,
`conditional_read`, `read_identity`, `read_body`, `full_body_check`, and
`completion`. Fixed codes are `clock_invalid`, `sdk_call_failed`,
`conditional_create_refused`, `identity_invalid`, `identity_changed`,
`body_invalid`, and `body_mismatch`. The sidecar contains no raw SDK error,
key, payload, or credential and leaves the response schema unchanged.
`sdkInvocations` counts attempted SDK calls; a rejected SDK argument may never
dispatch an upstream provider request. The sidecar never settles an unknown.

Raw originals, dispatch intents, replies, known anchors and unknowns remain
retained. No command retries, enumerates, deletes or automatically reconciles an
unknown. Repeated `status` reads only bounded owned private files.

## Runnable sequence after review

Use the source-built AOS Python executable; all paths are explicitly selected
owner-private inputs. Capture the live namespace first with the existing reader,
then invoke these commands promptly enough to retain the original TTL:

```text
<AOS Python> _hub-oci-sdk-anchor.py prepare
  --namespace-observation-file <new independently joined namespace receipt>
  --output-directory <new private original directory>

<AOS Python> _hub-oci-sdk-anchor.py dispatch
  --original-directory <same exact original directory>
  --socket-file <selected runner socket>
  --node-file <selected installed AOS Node>

<AOS Python> _hub-oci-sdk-anchor.py status
  --original-directory <same exact original directory>
```

Only the explicit `dispatch` phase can cause the one Put and subsequent read.
Unknown, expiry or lost-reply results stop the run and preserve originals; do not
invoke dispatch again. A new original needs a separately selected fresh run and
namespace scope. There is no anchor cleanup command.

After a positive actual observation, independently review the real installation,
namespace/report hashes, anchor identity and bounded clock facts. Use the shared
OCI-purpose registry-key encoder and separately reviewed signed OCI artifact.
Installation must verify purpose, reviewer, deployment, compiled source and
script before writing only `HUB_OCI_SDK_EMULATOR_ACCEPTANCE`; this anchor command
never writes that KV or `HUB_DIRECT_UPLOAD_ACCEPTANCE`. The actual Native/Worker
OCI loaders freshly conditionally read the selected anchor before business work.
Their guard-role challenge receipt and exact returned identity/body join are a
separate runtime gate.

Finally execute the genuine production OCI writer: signed container graph
preparation/finalization, stage-only publication, authenticated `/v2/token`,
chunked blob upload and digest completion, manifest/index materialization, tag
projection and replay/refusal checks. Retain actual API originals, SDK receipts,
Native inbound/outbound bodies and successful-handler joins. Anchor positivity
alone never proves these business cases or zero Native object-transfer bytes.

## Source validation and execution scope

The adjacent Node tests use controlled SDK functions to check original custody,
conditional arguments, exact identity/body checks, expiry, refusal and permanent
unknown behavior. Python tests check real local sockets/processes and protected
files, plus actual prepare/status CLI invocations. They start no Worker or VM and
perform no R2 SDK effect. Run them with the AOS-built Node/Python tools.

The fixture request retains the runner's 96KiB ceiling; original bytes are at
most 32KiB, namespace receipts 16KiB, SDK payload/read 1024 bytes, client replies
16KiB. The existing socket timeout and runner unknown policy remain intact.
This source freeze is runnable preparation only; actual new-source installation,
namespace/anchor, purpose acceptance and OCI workflow observations remain pending.
