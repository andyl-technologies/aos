# Local OCI SDK artifact staging

The owner-private fleet runner can store an independently verified OCI SDK
emulator artifact in `HUB_OCI_SDK_EMULATOR_ACCEPTANCE` and return its actual KV
readback bytes. This fixture operation grants no permission. It performs no R2
read, anchor creation, OCI business write, provider call or cloud action.

The source-built installer client must verify the exact artifact with the shared
Rust codec before this request and verify the returned bytes again. The actual
Worker OCI purpose loader must independently verify its signature, evidence,
current clock, installation and fresh anchor before any business effect. The
runner does not implement signature verification, evidence commitments, profile
digests or registry-key derivation in JavaScript.

## Fixed installation

Select `ociSdkAcceptanceRegistryKey` with the source-built OCI `RegistryKey`
command and include it in the original runner configuration **before** obtaining
namespace and anchor observations. This runner-only option is removed before
Miniflare parses the configuration; its original bytes remain covered by the
configuration SHA256. Never rewrite the configuration after observation or
relabel an older source, distribution or anchor as the new installation.

The OCI KV binding must use an explicit local string namespace in `kvNamespaces`.
Missing namespaces, array syntax, a remote/object-form OCI namespace, and aliases
with other configured KV bindings are refused. KV access uses both the fixed
binding name and the independently observed worker name. No generic Direct
acceptance KV is selected by this branch.

Staging requires explicit OCI opt-in, a separate configured reviewer key and
matching deployment, Worker/Native origins, provider capacity and bounded UTC
policy. The artifact's purpose is exactly `oci_documents`, its execution kind is
`emulated_managed_sdk`, and its evidence scope is exactly
`anchor_create_and_conditional_read`. That scope describes the original anchor
interval; it does not qualify business expiry refusal or Hosted storage.

Before and after storage, the runner reuses its version-pinned namespace observer
and compares the selected R2 mapping, configuration, runner, Miniflare module and
workers, Wasm, shim, workerd executable, and process lifetimes with the artifact's
installation pins. Build-derived source/script identities require the separately
retained authenticated Worker Clock join; the namespace observer alone does not
attest compiled runtime identity. Native executable, source/distribution NAR,
anchor, evidence commitments and signature validation remain shared Rust codec
and actual consumer responsibilities.

## Closed socket protocol

The request has exactly five fields:

```json
{
  "version": 1,
  "kind": "oci-sdk-acceptance-install",
  "artifactBase64": "<exact artifact bytes as canonical base64>",
  "artifactSha256": "<lowercase SHA256 of those bytes>",
  "key": "oci-sdk-emulator-v1-<selected 64 hex digest>"
}
```

Artifacts are bounded to 32 KiB of exact UTF-8. The socket request retains the
existing 96 KiB bound. Staging checks the fixed outer artifact, profile, evidence
and installation field sets against the selected shared schema. It compares
purpose and installation pins; it does not replace complete shared typed or
cryptographic validation. Raw UTC checks refuse outside the artifact's original
integer window, including after awaited operations. They do not cancel or drain
an already dispatched KV operation.

The successful reply has exactly eight fields:

```json
{
  "version": 1,
  "status": "stored",
  "key": "oci-sdk-emulator-v1-<selected 64 hex digest>",
  "artifactSha256": "<exact readback SHA256>",
  "byteSize": "<decimal artifact byte count>",
  "runnerPid": 123,
  "runnerStartTicks": "<decimal kernel process start ticks>",
  "artifactBase64": "<actual KV readback bytes as base64>"
}
```

The installer must join the socket peer and exact process lifetime, verify all
returned commitments, compare the original bytes byte-for-byte, and run the
shared verifier again. `stored` means byte storage only. There is no accepted or
ready field. Its maximum artifact size keeps the reply below 64 KiB.

Concurrent OCI staging requests on the private socket are refused. An existing
identical value is read back without another Put. An existing different value is
never overwritten. Changed readback, installation or expiry yields the existing
fixed refusal response. Such a refusal can occur after a Put and proves no
absence of effects. Retain the original request and all returned bytes; do not
automatically replay, delete, reset or substitute a different artifact.

## Source gates

Run `_hub-oci-sdk-acceptance-tests.cjs` with the AOS-built Node package. Its mock KV
and private socket cases exercise bounds, closed fields, configuration and
installation substitution, fixed KV selection, conflicts, exact readback,
post-await expiry, process continuity and concurrent request refusal. Deliberately
unsigned controlled bytes verify that storage never claims acceptance. These
cases contain no Miniflare runtime, real KV/provider traffic or business evidence.
The existing namespace and anchor gates remain separate fixture contracts.
