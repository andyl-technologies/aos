# Garage patches

## SQLite writer transactions

`0002-sqlite-writer-transactions.patch` and `sqlite-writer-transactions.rs`
modify Garage 2.3.0 under its AGPL-3.0 license. The ordinary package and its
fleet variant both apply this patch.

The SQLite adapter already serializes transactions as writers within one
adapter instance. Starting an immediate SQLite transaction also reserves the
database writer before any reads. A deferred transaction can read a snapshot,
allow another connection to commit, and then fail its write upgrade with
`SQLITE_BUSY_SNAPSHOT`; waiting longer cannot repair that snapshot. This patch
changes transaction entry without retrying the transaction body or changing
busy timeouts, durability, package features, or the database backend.

The `integration.garage-sqlite-transactions` check runs the upstream database
library tests, including a deterministic regression. After the adapter reads,
a separate connection attempts a write with a zero test-only busy timeout.
The regression requires the adapter to hold the writer reservation, commit
its own update, and release the reservation so the other connection can write.
The original deferred transaction fails this regression.

## Fixture refusal disposal

`0001-fixture-refusal-drain.patch` and `fixture-refusal-drain.rs` modify Garage
2.3.0 under its AGPL-3.0 license. They are used only by the separately named
`garage-fleet-refusal-drain` derivation in
`tests/fleet/_hub-garage-refusal-drain.nix`. The refusal-disposal changes do not
alter the ordinary Garage derivation,
features, service module, or configuration.

The patched variant also defaults to the ordinary behavior. Its S3 setting is:

```toml
[s3_api]
fixture_no_such_upload_drain = true
```

When enabled, UploadPart validates the upload before polling its request body.
Only a genuine `get_upload` `NoSuchUpload` enters refusal disposal. The handler
retains the existing signature/checksum stream, discards frames without
collecting the body, and requires EOF and successful checksum completion before
returning that same error. It never enters the part/version write pipeline on
this branch. Valid uploads still use the existing parser, storage, and checksum
code. With the setting absent or false, the original concurrent upload lookup
and first-block read remain intact.

Disposal admits at most 64 MiB and has one absolute 90 second deadline covering
the first frame, all remaining frames, and checksum completion. These are
fixture bounds, not new limits on supported successful Garage uploads. The
fleet front door already admits 64 MiB and the conformance client has a 120
second request timeout. A transport failure, excess body, checksum failure, or
deadline error does not return `NoSuchUpload` or establish a completed drain.

The checksum stream retains a channel sender even after EOF. Disposal drops
that stream before joining its existing checksum task. An invocation-owned
guard aborts the task on error or cancellation; this does not assert that an
already running checksum operation or remote socket has drained.

## Focused verification recipe

The fixture derivation retains the ordinary Garage source hash, vendor input,
features, and build flags, and adds a library test phase selecting
`garage_api_common` and `garage_util`'s `fixture_refusal` tests. The authored
tests verify that the setting defaults to false and exercise real
`ReqBody::streaming_with_checksums`, exact 64 MiB admission, excess bytes,
arithmetic overflow, checksum/transport/deadline failure, body-owner
cancellation, and pending checksum-task cancellation. They have not been run
merely by authoring this recipe.

After source review, build this derivation using the accepted immutable runtime
package set and this fixture source. Record the actual patched Garage ELF and
its source/patch/vendor inputs. Use `_hub-hybrid-runtime.nix` to keep the Native,
Worker, client, and other runtime tools on the separately selected runtime
source. The fixture changes its registered Garage tool closure and rendered
S3 configuration; do not label it as the original unpatched Garage artifact.

For the narrow real TLS check, use the existing S3/Worker setup and the unchanged
`aos-hub-provider-conformance run --config CONFIG --journal JOURNAL --output
OUTPUT` command, with one fresh private configuration, prefix, policy, and
journal. The current S3 nginx method map, TLS verification, GET holders, request
buffering setting, and client executable remain unchanged. Do not reuse a
failed journal or retry an unknown original.

Retain the actual intent, response, and observation for the complete sequence:

- Normal source parts and Complete succeed; bad checksum is refused.
- `late_part_after_complete` sends the original signed 8 MiB part unchanged and
  obtains the real `404/NoSuchUpload` response through TLS.
- Source HEAD, full/range reads, and final read retain the original size and
  digest; the wrong conditional range obtains its genuine refusal.
- Abort is positively acknowledged, then `late_part_after_abort` sends the
  unchanged part and obtains the real `404/NoSuchUpload` response.

The refusal branch's placement before every part/version write is a source
invariant. The TLS observations establish actual transport behavior and
provider-visible object integrity; they alone do not count internal database
writes or establish full fleet, capacity, timing, or remote-drain qualification.
Keep failed, absent, and incomplete responses unknown. No response, status,
checksum, request geometry, or conformance predicate is synthesized by this
fixture.
