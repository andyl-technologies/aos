# Local OCI SDK namespace observation

This fixture observer identifies one installed Miniflare R2 SDK attachment for
an OCI-specific emulator test. It does not establish Hosted R2 identity, generic
Managed Direct acceptance, mirror authority, presigning authority, or provider
behavior. The existing guard observation and External acceptance installer keep
their original purpose and schema.

## Installed inputs and request

The runner accepts an optional `ociSdkNamespaceObservation` configuration object
with exactly `sourceStorePath`, `wasmPath`, and `workerdPath`. The selected Wasm
must be `index.wasm` beside the actual configured `scriptPath`. The source must
be an existing immutable store directory. The actual workerd child must match
the selected executable and remain the same owned process throughout capture.

The owner-private control socket accepts exactly:

```json
{"version":1,"kind":"oci-sdk-namespace-readback"}
```

Absent selections, unknown fields, unsupported APIs, changed implementation
bytes, remote bindings, duplicate namespace aliases, malformed IDs and changed
processes refuse. Existing `namespace-readback` and External installation
requests remain separate.

The implementation is pinned to the installed Miniflare
`5.20260801.0-alpha` module and its R2 bucket and object-entry workers by SHA256.
It uses the actual `R2OptionsSchema` and `namespaceEntries` to normalize the
selected `REGISTRY_BUCKET`, selects that live proxy with `getR2Bucket`, and
obtains its object ID through the installed internal namespace proxy:

```text
_getInternalDurableObjectNamespace("r2", "r2:bucket", "R2BucketObject")
    .idFromName(normalizedNamespaceId).toString()
```

This internal API is deliberately version-specific. The pinned plugin connects
the selected namespace ID to `MINIFLARE_NAMESPACE`, the namespace unique key
`miniflare-R2BucketObject`, and the R2 persistence directory. These operations
select proxies and derive an ID; they call no object SDK method. No SQL storage
inspection, object enumeration, object creation, read, write or deletion occurs.

## Closed private receipt

The response has exactly these fields:

| Group | Fields |
| --- | --- |
| Purpose | `version`, `observationScope`, `observedAt` |
| Runner | `runnerPid`, `runnerStartTicks`, `configurationSha256`, `runnerSha256` |
| Implementation | `miniflareVersion`, `miniflareModuleSha256`, `miniflareEntryWorkerSha256`, `miniflareBucketWorkerSha256` |
| Installed artifact | `shimSha256`, `wasmSha256`, `wasmByteSize`, `sourceStorePath`, `buildDerivedSourceDigest`, `buildDerivedScriptVersion` |
| Attachment | `workerName`, `bindingName`, `namespaceId`, `namespaceObjectId`, `namespaceUniqueKey`, `persistenceRoot` |
| Child process | `workerdPid`, `workerdStartTicks`, `workerdExecutableSha256` |

`version` is numeric `1`; `observationScope` is
`oci_sdk_emulator_namespace_readback`. PIDs are positive integers; byte sizes and
start ticks are canonical decimal strings. SHA256 and object IDs are lowercase
64-hex strings. Namespace names are bounded ASCII identities. `observedAt` is
an actual UTC observation, not an authorization clock.

The separate `_hub-oci-sdk-namespace.py` reader checks the actual socket
`SO_PEERCRED` PID/UID, exact selected Node command, runner and child lifetimes,
child parentage and independently streamed installed hashes. It verifies the
configuration and requires an independently selected identity document with
exactly `sourceDigest` and `scriptVersion`. It does not authenticate that
identity document itself. The caller must retain the genuine Worker identity
receipt and its authentication/source provenance.

The `buildDerived*` fields hash the selected source store path according to the
package's build convention. They are build-input observations until joined to
the independently authenticated running Worker identity. Hashing a file does
not prove that every byte is currently resident in an isolate.

Raw paths, PIDs and start ticks remain in an owner-private receipt. A reviewed
public OCI artifact should commit that receipt's SHA256 and select the bounded
mapping and installation facts it actually verifies. It must not copy private
paths or treat an environment/bucket label as provider identity.

## Bounds and remaining gate

The control request retains the existing 96KiB request bound. The independent
reader bounds the reply to 16KiB, configuration to 1MiB, selected identity to
256KiB, shim to 2MiB, Wasm to 64MiB and executable to 512MiB. Hashing uses 1MiB
blocks. The socket has a 15-second reader timeout; process and configuration
joins are rechecked after capture. Reports use create-new owned private files.

A separate positive namespace anchor is still required. That future gate must
retain its exact version, ETag, size and full SHA256 and freshly read it through
the selected SDK attachment. The SDK's conditional read is ETag-based; the
returned version must also equal the selected anchor version. This observer
neither creates the anchor nor authorizes that effect.

## Controlled source tests

Run the Node tests with the source-built AOS Node executable and
`AOS_OCI_OBSERVER_MINIFLARE` set to the selected installed AOS tooling root. Run
the Python tests with the source-built AOS Python executable. The tests inspect
actual installed schema/plugin source, exercise a controlled namespace proxy
without SDK effects, and use real local socket/process/custody checks.
Controlled fake IDs and callback replies are test fixtures, never runtime
namespace or acceptance evidence. A live installed Worker capture remains a
separate required gate.
