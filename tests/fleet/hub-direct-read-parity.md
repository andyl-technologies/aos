# Fixed read, index and public-cache cases

`_hub-direct-read-parity.py` adds a separate read window after the normal
publisher has completed and Native has committed its authoritative indexes.
It uses the real public routes through the selected Worker-fronted Native
origin. Native-only and Worker-only companions publish the same signed source
and expose their ordinary public routes. The helpers do not replace the main
three 2 GiB objects, 12,535 metadata objects, publisher commands, latency window
or upload counters.

These are callable fixtures, not a runtime qualification report. Local tests
use controlled source files, HTTP/cache doubles and one actual loopback socket
timeout. They do not qualify TLS, IAM, a provider, an installed Worker, or
Native bulk-byte absence. A complete final run still requires one reviewed
runtime source and its actual installed artifacts, with a separately pinned
fixture source. The selected five-machine input must explicitly set both
`externalDirect = true` and `separateDatabase = true`.

## Corpus and authoritative indexes

`prepare_direct_documented_surface` extends a separate genuine APR release
with package documentation produced by `apr publish --documentation-base-lib`.
It invokes the actual APR release and signature verification commands, then
retains the document identified by the signed package TOML. It requires
nonempty real option documentation within the production 256 KiB cache bound.
It selects APR's supported XDG config/data/cache roots for the actual prepared
registry and captures that clone's existing commit identity, while preserving
the inherited home. Missing local identity refuses before the new publication.
The caller supplies the actual package, version and module-library inputs;
there is no generated stand-in document. The generated guest program has a
source syntax gate, but its APR commands still need runtime execution.

The caller must also supply the genuinely published OCI graph and exact
independent source files. Missing document, container or companion input
refuses full parity. Neither an OCI SDK acceptance artifact nor a bucket label
equates Miniflare R2 with an external S3 provider.

The closed selection names one registry, package and 64-hex source commit,
three distinct HTTPS origins, and exactly five objects. Each object selects
an owner-held regular file, full SHA-256, numeric byte size and fixed relative
route. Source files are bounded at 4 MiB and checked before dispatch.

| Class | Fixed route | Observations in each mode |
| --- | --- | --- |
| Git | `objects/<2 hex>/<62 hex>` | full GET, HEAD, range 6–13 |
| Package | `nar/<name>.nar[.<compression>]` | full GET, HEAD, range 6–13 |
| Metadata | `<32-character store hash>.narinfo` | full GET, HEAD, range 6–13 |
| Documentation | `-/api/v1/documentation/sha256:<64 hex>` | canonical JSON GET |
| Container | `v2/<repository>/blobs/sha256:<64 hex>` | full GET, HEAD, range 6–13 |

Documentation and machine objects use the registry slug prefix. Distribution
uses its actual repository route. The document and blob routes must match
their independent content digest. Canonical documentation is bounded query
content; its API has no object-range contract. An unsupported HEAD or range
for any required machine object is a refusal, not a fallback full-body pass.

`run_direct_read_parity` performs 39 fixed requests. Full responses must equal
the retained source bytes. HEAD must report the same content length, and a
range must return actual status 206, eight exact bytes and matching
Content-Range/Content-Length. Redirects, interim blocks, duplicate selected
headers and changed representation encoding refuse.

`run_direct_semantic_read_parity` performs 12 further fixed GETs: package
list, the selected package detail, channels and releases in each mode.
Responses must be nonempty JSON and include the selected package's versions.
Every decoded field is compared across modes; no local IDs, unknown fields
or timestamps are silently removed. Duplicate JSON fields and nonfinite
numbers refuse. This observable equality complements the authoritative SQL
comparison and does not authenticate the signed source by itself.

`capture_direct_full_index_parity` uses the existing fixed
`registry_index_observations` projector and independently configured readers.
It retains all three private snapshots before asserting equality. The index
must be fresh at the selected source commit. Required package/release/channel,
artifact, documentation, container graph/evidence/provenance and browse
projections must be nonempty. All returned tables are compared, including
optional projections, with the projector's existing handling of local IDs.

## Actual public documentation cache

Install `_hub-worker-cache-observer.cjs` as an explicit immutable fixture
module before starting the fresh runner. Select these runner-only options in
the original configuration:

```json
{
  "publicDocumentCacheObserverPath": "<installed fixture module>",
  "publicDocumentCacheCase": {
    "registrySlug": "<selected public org/registry>",
    "documentSha256": "<raw full SHA-256>",
    "bodyBytes": 256,
    "assetVersion": "<actual eight-hex installed console version>"
  }
}
```

`bodyBytes` is the actual document size, not a fixed fixture value. The
configuration also contains the existing owner-private `acceptanceSocketPath`.
The runner strips the two cache-only options before Miniflare parsing; it
loads the selected module only for the cache callback. Existing guard, source,
OCI namespace, anchor and typed staging callbacks retain their contracts.

The observer pins the installed Miniflare module, package version
`5.20260801.0-alpha`, and its two Cache API worker files. It uses actual
`runtime.getCaches().default.match` and `delete`. It never calls cache `put`,
purges a namespace, admits a response, or changes a provider object. Unsupported
installed APIs or ambiguous multi-worker configuration refuse.

The exact request is `{ "version": 1, "kind": "public-document-cache-readback" }`
or the same shape with kind `public-document-cache-evict`. The URL/key is
derived from the configured public origin, deployment, actual asset version,
full documentation URL and fixed request variants. There is no caller-supplied
URL/key/variant. Deletion requires an existing bounded entry whose full bytes
match the selected document, then independently observes absence.

The closed 19-field response contains version, observation scope, kind,
runner PID/start ticks, configuration/module/API/shim hashes, selected Worker,
document URL/key hashes, actual observation UTC and `before/deleted/after`.
Cached entries contain exact `bodySha256`, decimal `byteSize`, and decimal
`expiresAtUnixSeconds`; production stores expiry in seconds. No credentials,
body or raw cache URL appears in the response.

`direct_document_cache_control` retains raw request/reply files on the
owner-private socket and joins actual SO_PEERCRED PID/UID/start ticks. Its UTC
bracket must contain the reported observation. The read window also requires
an independently selected complete cache installation identity; repeated
observations cannot silently change configuration, process, module, shim,
selected document or derived key.

Run `run_direct_full_read_window` with that identity, the real transport,
private bearer/cookie header files, a private registry containing the same
document, and the three actual SQL readers. It deliberately runs the cache
case before the other document reads:

1. Require actual cold Cache API state.
2. GET the public document: miss, actual entry readback, then public hit.
3. GET with bearer and cookie: both bypass shared-cache hits.
4. Authenticate the existing private document through the exact
   `DocumentationService/GetDocumentationArtifact` API. Compare its canonical
   bytes and ETag, then require anonymous 404 for that exact private document
   with no public-cache hit.
5. Wait for the actual stored UTC expiry, bounded by 65 real seconds; no clock
   or cache timestamp changes. Require a miss and fresh admission.
6. Delete only the exact selected public key, read back absence, require
   refetch/miss and a rebuilt hit.
7. Perform the fixed object and semantic reads.

`DirectReadHttp` performs one source-built curl dispatch per request, with
strict TLS, no retry/redirect/config-file override, fixed body/header bounds
and retained private request, response, stderr and timing files. Authentication
headers stay in those private files. The runner's cache observation is not
cryptographic authorization or evidence that Native was bypassed. Public
hits do not imply outage survival; authenticated/private reads must still
respect the actual Native authority path.

## Refusal cases and remaining producers

`_hub-direct-read-timeout-provider.mjs` is a separate confined adapter for
the owning local TLS provider. Call `read` **only after** that provider's real
request signature verification. Select one already completed 16-byte–32 MiB
object under `.aos-direct-read-qualification/<run digest>/timeout/object`,
with its actual version, strong ETag, size and full hash. Exactly one GET
with that version and If-Match may arm the case. Replays, changed source,
other methods and different conditional identities refuse. The adapter has
no upload, replacement, delete or administrative authority.

The selected request receives no response headers/body. Actual start and peer
closure are logged independently; a 35-second fixture timeout closes its own
socket without substituting HTTP 504. The journal reports offered application
bytes only. Peer closure does not prove the Worker's error, physical drain,
SDK success or global provider traffic. The local loopback test demonstrates
the adapter/socket behavior, not TLS/SigV4/Worker qualification.

`assert_direct_read_refusals` requires the three named observations:
provider timeout, stale placement and Worker revision mismatch. It verifies
actual original/received commitments, retained non-success reply, unchanged
selected authoritative-index snapshot and stable complete log-prefix custody. Timeout events
must join one received conditional request inside the real observation window.
The revision mismatch requires no events in its selected provider window.
This is a consistency check; it does not fabricate an authenticated original
or establish complete provider capture merely from a digest.

The stale-placement and revision producers remain explicit dependencies:

- Hold a genuine normal Native storage plan before Worker dispatch; apply a
  genuine reviewed placement revision through existing Plan/Apply APIs, then
  release the exact original and retain Native's commit refusal, unchanged
  authoritative index, real placement-ID/revision observations and provider
  window. A previously admitted read may still dispatch through its physical
  lease cutoff. This placement case does not assert immediate Worker refusal
  or zero provider requests. A binding-generation pre-dispatch refusal needs
  a separate genuine acknowledged binding-control/authority-floor change.
- Select a genuinely installed mismatched Worker/profile revision with real
  source identity. A changed hash dictionary or forged Clock reply is not this
  test. The selected actual handler/profile must reject before provider work.

These producers, the provider's signature-verified timeout hook and the final
document/container publication setup must be connected under a reviewed
runtime tuple before the respective cases can pass. Missing/unsupported cases
remain pending and cannot upgrade the final launch ledger.

Every read/cache/refusal report retains `nativeBulkBytes = null`. New browse,
documentation and Distribution routes remain unclassified until the selected
source codec and actual authenticated handler/original/header/body/provider
joins cover them. Status, equal bytes, source dictionaries and cache hits do
not establish current IAM, purpose admission or a zero-byte Native boundary.
