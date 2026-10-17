# Hosted signed-corpus reads

`aos-hub-hosted-read` observes existing installations and retained publication
files. It does not install, upload, sign, change permissions, stop a service,
evict a cache, or retry a request. Private coordinates and credentials belong
only in operator-owned input files, never in repository examples or reports
intended for publication.

```text
aos-hub-hosted-read run --selection REFERENCE.json --output-dir NEW_PRIVATE_DIRECTORY
aos-hub-hosted-read assess --selection ASSESSMENT_REFERENCE.json --output-dir ANOTHER_NEW_PRIVATE_DIRECTORY
```

Both commands return `2` after completed observations and `1` on failure or an
unknown transport outcome. Exit `2` is not hosted qualification. Each output
directory is fresh, owned and private; raw response prefixes and error receipts
are retained before assertions. No capture failure turns missing bytes into zero.

## Inputs

The CLI selection file contains one reference, with this closed format:

```json
{"file":"/absolute/operator-owned-file","sha256":"64 lowercase hex characters","byteSize":"canonical decimal byte count"}
```

Referenced inputs are bounded owner-private regular files without final symlinks
or hardlink aliases. The run selection contains these exact fields:

| Field | Meaning |
| --- | --- |
| `version` | Integer `1` |
| `corpusId`, `windowId` | Fresh 32-character lowercase hex identities, shared with actual capture policy |
| `startsAt`, `expiresAt` | Actual Unix seconds; original window at most 600 seconds |
| `runtime` | Exact measured `runtimeCodecRevision`, `workerSourceDigest`, `sourceArchiveSha256`, `nativeExecutableSha256` |
| `sourceTree` | Actual 40-character Git tree commitment for that runtime source |
| `paritySourceSha256` | Actual installed `_hub-direct-read-parity.py` bytes |
| `hostedWorkloadSourceSha256` | Actual installed `hosted-workload.py` bytes |
| `signedPublication` | Reference to the existing independently reviewed signed publication receipt; retained, not reauthenticated here |
| `corpus` | Existing signed-read comparator selection described below |
| `deployments` | Three selected installation pins and actual before-readback references |
| `curl` | Source-built immutable executable `{file, sha256}` |
| `trustFile` | Private bounded CA reference, or `null` for ordinary curl trust |
| `bearerHeaderFile`, `cookieHeaderFile` | Absolute private header files consumed only by curl; no signing key input |
| `privateRegistrySlug` | Distinct existing private registry containing the same canonical document |

`corpus` reuses the fleet's exact closed schema:

```text
{version:1, sourceCommit:<signed registry SHA-256 commit>, registrySlug,
 packageName, origins:{hybrid,native_only,worker_only},
 objects:{git,package,metadata,document,container}}
Object = {relativePath,file,sha256,byteSize}
```

The three origins are distinct HTTPS origins. Every selected file must match
its independent size/hash. Git, NAR, narinfo, documentation and OCI route grammars
come from the unchanged signed-read helper; responses are capped at 4 MiB.
Canonical documentation must fit the existing 256 KiB cache admission.

Each `deployments` member contains exactly `deploymentId`, `moduleSha256`,
`configurationSha256`, `processEpoch` and a `before` reference. Native-only may
use `moduleSha256:null`; it must not invent a Worker module. The readback format
is closed:

```text
{version:1,mode,origin,deploymentId,moduleSha256,configurationSha256,
 processEpoch,runtime,sourceTree,observedAtUnixNs:<canonical decimal>}
```

Readbacks must match the selected installation and original window. Comparing
retained facts does not authenticate their producer or establish current process
authority. Missing independent installation/actor/SQL proof remains explicit.

## Actual reads and cache assertions

The driver first requests the public canonical document without credentials,
requires no cache-hit marker, then requires a warm `x-aos-front-cache: hit` with
identical bytes. Bearer and cookie requests must return those exact bytes without
a shared-cache hit. A private documentation query must return the actual same
canonical JSON and ETag; its anonymous browse route must return `404` without a
shared-cache hit. The internal expiry header must not escape on public reads.

This checks the observed fill/hit/bypass sequence. It does not inspect hosted
Cache API contents or prove an initially empty cache. Missing or changing
`cf-ray` locations retain the location uncertainty. No Miniflare cache socket
or local process evidence is used as hosted state.

Then all three modes execute exact full reads, object HEADs, fixed
`Range: bytes=6-13` requests, and complete package/channel/release JSON queries.
Documentation is bounded query output, not an object-range contract. Assertions
compare full bytes and complete query values, without omitting differing fields.

Curl retains strict TLS, identity encoding and no redirect or retry. Its private
header files remain open with stable descriptor custody across the call; their
values are not decoded or copied into receipts. The existing process supervisor
bounds captured stdout at 16 MiB and stderr at 64 KiB, and owns cancellation.
Parsed headers and bodies retain their stricter 64 KiB and 4 MiB bounds. A partial
response is a consumed prefix, never a successful EOF or an empty result.

## Later installation and fanout joins

The assess selection contains exactly:

```text
{version:1,readSelection:<reference>,readReport:<reference>,
 afterReadbacks:{hybrid:<reference>,native_only:<reference>,worker_only:<reference>},
 fanoutInvocation:<reference or null>}
FanoutInvocation = {version:1,executable:{file,sha256},selection:<reference>}
```

After readbacks must occur after the final actual response and before the
original cutoff, match the same installation epoch, and not be future-dated.
Offline assessment issues no reads and does not renew a deadline.

The only fanout executable is the canonical immutable installed
`aos-hosted-byte-assessment` wrapper. Its existing package reader verifies codec,
runtime and producer-source commitments. The capture policy must select the same
corpus, window, source tree and original times; index transcripts, when supplied,
must select the same signed registry source. An arbitrary private adapter or JSON
report cannot replace the actual successful assessment invocation.
The invocation receives the checked selection bytes from the held private output
directory, rather than reopening the operator's selection pathname.

The report retains existing independent receiver/codec joins and actual Native
execute records: call and plan identities, offered request count/hash, exposed
reply count/hash/EOF, every selected attempt, and final SQL commitments. Unknown
authenticators, absent receivers, unobserved GET ownership, current SQL authority,
provider work and capture completeness retain their existing unknown states.
The retained read report's producer authority also remains unknown; matching its
source commitment and selected bytes does not authenticate a runtime producer.

Outage injection and outage-producer validation are outside this slice. `outage`
remains `null`; cached public document availability cannot imply permission to
read an R2 object while Native is unavailable. Object-byte caches still require
fresh Native authorization. `qualification` and `nativeBulkBytes` remain `null`.
