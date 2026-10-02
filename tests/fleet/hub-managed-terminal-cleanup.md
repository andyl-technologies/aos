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
outputFile, placementPrefix, uploadId, ordinal, expectedOriginalSha256, profile
```

It attaches to the already-existing exact serving schema without migrations;
SQLite attaches read-only. It selects only the real terminal pending upload
and retained chunk, checks current Managed placement/binding/Delete capability,
and uses the production database constructor for the opaque cleanup claim.
It neither inserts SQL nor invokes a provider to create test bytes.

`phase = observe` produces only the exact SQL original and its hash. Later
`dispatch_unknown` or `replay_positive` must select that same original hash.
They use the existing production cleanup method, independent physical guard
key and strict TLS with the actual pair root certificate. An unknown first
exchange is reported as unknown; a positive later exchange is reported only
after the production reply authentication. The claim must still be unchanged
after either attempt, and private receipt output is exclusive.

The Fleet controller owns deliberate loss of the completed response, exact
runner cold restart, actual authenticated transport originals/replies and
per-key SDK brackets. The helper reports `providerSdkCalls = null` and
`sqlCleanupSettled = false`; it cannot establish zero SDK replay or SQL
settlement from a Native boolean. Normal recovery later performs the actual SQL
cleanup transition, which the controller must independently observe. An
unknown SDK event or missing bracket/footer remains unresolved.

The current source capsule is preparation only. Node tests control KV and
namespace interfaces without starting Miniflare; Native helper compilation and
the actual pair/lost-reply/cold-replay run require the accepted complete source
and measured common artifacts. No custom provider facade is used.
