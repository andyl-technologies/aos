# Managed terminal cleanup fixture hooks

These hooks use the actual pinned Miniflare runner, its configured R2 namespace
and persistent `HybridObjectGuard`. They select a confined test identity; they
do not create provider objects, qualify Hosted behavior or grant Delete
permission. Normal Distribution work must first produce the terminal SQL upload
and immutable chunk. The actual conditional-delete probe must independently
record a current valid capability with NULL credential purpose/generation.

## Private runner installation

Initial do-e2e configuration pins these exact bindings before observation:

```text
HUB_MANAGED_OCI_CLEANUP_FIXTURE_PREFIX=qualification/oci-terminal-cleanup/<run>
HUB_MANAGED_OCI_CLEANUP_FIXTURE_NAMESPACE=<actual configured namespace ID>
```

The runner-only `managedCleanupInstallerPath` selects the reviewed
`_hub-managed-cleanup-install.cjs` module. It is removed before Miniflare option
parsing. Existing OCI installer and anchor operations remain separate.

After actual namespace/anchor/Clock observations, the existing owner-private
acceptance socket accepts exactly:

```json
{"version":1,"kind":"managed-oci-cleanup-fixture-install","recordBase64":"<exact UTF-8 bytes>","recordSha256":"<SHA-256>"}
```

The decoded value is the closed Rust fixture record `{version, selection,
profile}`. `selection` contains `deploymentId`, `placementPrefix`,
`protectedProfileDigest`, `sourceDigest`, `scriptVersion`,
`uncertaintySeconds`, `issuedAt` and `expiresAt`. `profile` is the actual raw
`OciSdkEmulationProfile`, including its independently observed anchor. The
shared Core helper computes the distinct fixture profile commitment; this
installer does not implement a second canonical digest or treat the raw
profile as Delete permission.

The installer measures the actual serialized record, requires at most 4096
bytes and exact UTF-8/base64/SHA, and checks the closed fields, initial
prefix/namespace, configured audience/clock/capacity and actual runtime
namespace/source/script. It stores only fixed key
`managed-oci-terminal-cleanup-fixture-v1` in existing
`HUB_OCI_SDK_EMULATOR_ACCEPTANCE`, then requires byte-equal KV readback and
unchanged runner/workerd/configuration/module identities. A different existing
record refuses rather than overwriting it. The original at most 600-second
selection window is rechecked around every await and is not renewed.

The response retains exact record bytes/hash/count, runtime/namespace/source
coordinates and installer module hash. No R2 SDK method is invoked. Actual
profile serialization/installation must be measured in the real pair;
controlled unit fixture byte sizes are design checks only.

## Ignored Native helper

`storage_work::oci_cleanup::controlled::actual_managed_terminal_cleanup_pair`
is an explicitly selected ignored test, compiled from the same reviewed
Native source. It requires owner-private input path in
`AOS_MANAGED_CLEANUP_CONTROLLED_INPUT`. The closed JSON fields are:

```text
version, phase, databaseUrlFile, workKeyFile, guardKeyFile, tlsRootFile,
outputFile, placementPrefix, uploadId, ordinal, expectedOriginalSha256, profile,
lostRequestFile, lostRequestSignatureFile, lostReplyFile, lostReplySignatureFile
```

It attaches to the already-existing exact serving schema without migrations;
SQLite attaches read-only. It selects only the real terminal pending upload
and retained chunk, checks current Managed placement/binding/Delete capability,
and uses the production database constructor for the opaque cleanup claim.
It neither inserts SQL nor invokes a provider to create test bytes.

`phase = select_original` selects one actual pending terminal upload from the
fresh placement prefix; it refuses supplied upload identity. `observe` retains
an explicitly selected current original. `dispatch_unknown` and
`replay_positive` must select that same original hash. They use the existing
production cleanup method, independent physical guard key and strict TLS with
the actual pair root certificate. Unknown remains unknown; a later positive
requires production reply authentication and an unchanged SQL claim.

`authenticate_lost_reply` reads the actual bounded request/reply bodies and
signature files. The existing Core canonical request and independent physical
reply validators authenticate them against the current SQL original, raw
profile, issuer source/script and original request cutoff. It dispatches no
provider request. Its output binds the exact offered request SHA and positive
opaque object/physical receipt. Metadata authentication cannot restore an
expired request or grant permission.

`settle` uses the normal `recover_expired_oci_work` API on the existing fresh
PostgreSQL pair. It first checks that every selected pending cleanup locator
belongs to the exact pair prefix. It requires the observed upload to reach
actual complete cleanup with its staging locator cleared, then retains the
normal recovery summary. It inserts no upload or capability and performs no
custom cleanup CAS. The production 60-second recovery controller remains
active: a changed claim refuses rather than disabling that controller.

## Initial transport and actual readiness

The Fleet controller includes `_hub-managed-terminal-cleanup.py` and calls:

```text
prepare_managed_cleanup_loss(native, tools, prepared, worker_address)
await_managed_cleanup_loss(native, tools, prepared, process)
run_managed_terminal_cleanup_window(native, worker, client, tools, prepared,
    processes, boundaries, controls, setup, container_source, publication,
    installation, refresh_token)
```

Preparation precedes Clock, namespace and anchor observations. The existing
Native outbound capture proxy initially routes only exact
`/_internal/storage/managed-oci-cleanup/v1` to loopback `127.0.0.1:4660`.
`_hub-managed-cleanup-loss.py` connects directly to the initially selected
separate Worker address on port 4643 with strict TLS, SNI `localhost` and the
actual selected CA. All other traffic retains ordinary forwarding. Configuration
is never rewritten after observations, and this route cannot recurse.

Requests require one bounded Content-Length, no query or transfer encoding,
and one `x-aos-managed-oci-cleanup-signature`; request and reply bodies are each
at most 16 KiB. The actual Host and existing `x-aos-fleet-request-id` and
`x-aos-storage-call-id` values are preserved. These correlation headers grant
no authority; a missing value is never manufactured. At most 32 exchanges are
retained by this confined listener. Actual private body/signature files and
TLS peer certificate hash remain available even when downstream delivery is
lost. Existing whole-window proxy capture remains independent and may be
incomplete for that delivery.

Only after its fixed socket is bound/listening does the owner-private listener
write exclusive `ready.json`, with this closed shape:

```text
version, scope, pid, startTicks, ownerUid, configurationSha256,
listenerSourceSha256, listenAddress, route
```

The readiness validator checks the actual recorded launch lifetime and
executable/argv/environment, then the source/configuration/route record. A PID
alone is not readiness. Preparation returns the exact argv, executable hash,
configuration hash, readiness path and listener source hash for the pinned
Fleet launcher. No upstream or provider operation occurs during preparation.

## One completed-response loss and cold replay

The private once-only arm binds the real observed SQL original SHA, protected
profile commitment and helper inputs. The selected request retains its
original at most 30-second delegation. A different original, changed profile,
stale arm or deadline refuses before forwarding the armed request.

After receiving a complete actual 200 response, the listener invokes only the
same-source Native metadata authentication phase. A positive signed reply must
name that exact request/current original before the listener closes downstream
without sending any reply bytes. Generic errors, incomplete responses or a
failed signature are never deliberate completed-response loss. The Native
attempt remains unknown; private upstream observations retain the positive
physical outcome separately.

`_hub-managed-cleanup-runtime.py` rechecks the original Node and workerd
lifetimes and direct parent relationship, opens exact pidfds, and stops only
those two lifetimes. It restarts the exact argv/environment with unchanged
configuration, persistent stores and module/source/namespace pins. Its output
appends to the same owner-private Worker log inode; the cold receipt retains
the old byte offset, and capture windows keep separate before/after process pins. A new
owner-private readback must match those pins. It never signals by process name
or resets provider state. The installed fixture record and original selection
window remain unchanged across restart.

The fresh signed replay must preserve the same opaque R2 object identity and
physical positive receipt. Existing `managed_terminal_cleanup` SDK brackets
must show the original actual head/get/delete calls and a complete healthy cold
replay scope with zero new calls. Missing footer, unknown result, altered SQL
claim or incomplete transport remains unresolved. Later normal recovery must
settle the real SQL cleanup. Native bulk accounting stays `null` pending its
independent full-window classifier; provider counters are not Native bytes.

## Selected helper inputs and evidence scope

The called adapter requires installed same-source tools
`managedCleanupLossListener`, `managedCleanupRuntime`,
`managedCleanupNativeHelper`, `managedCleanupNativeHelperProvenance` and
`commonSourceStorePath`, alongside the existing Worker source/namespace/reviewer
and capture tools. The auxiliary helper provenance is exactly:

```text
version, commonSourceStorePath, workerFilteredSourceStorePath,
testExecutableSha256, testExecutableBytes
```

The byte count is a canonical decimal string in 1..512 MiB and must equal the
actual installed test ELF. The two source paths must match the accepted common
runtime and actual do-e2e filtered input. Historical diagnostic test binaries
cannot substitute for this selection.

Controlled Python tests exercise real loopback TLS forwarding, actual post-bind
readiness and refusal paths. Their authentication callback is explicitly
controlled test source; it is not a real pair signature, provider or permission
proof. Native compilation establishes type/registration evidence only. Actual
Miniflare record installation, normal terminal SQL/Delete probe, response loss,
cold replay, SDK brackets and settlement require the accepted complete source
and measured common artifacts. No custom R2 facade is used.
