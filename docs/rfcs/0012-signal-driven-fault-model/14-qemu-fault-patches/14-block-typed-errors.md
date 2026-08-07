# 14.14 — Typed block errors

`0060-crucible-block-typed-errors.patch` carries a closed storage result from
the Crucible block worker through the GPL plugin callback and returns the exact
Linux errno from QEMU's `crucible-shmem` block driver. The executable protocol
definitions are [`BlockErrorCode`](../../../../../crates/crucible-device/src/block/codec.rs)
on the host side and `BlockResponseErrorCode` in
[`block_io.rs`](../../../../../crates/crucible-qemu-plugin/src/block_io.rs) on
the plugin side. The two definitions are intentionally independent across the
process/license boundary and are checked for byte-for-byte semantic agreement.

## Capability and activation

The patch applies only to requests using the explicitly selected
`crucible-shmem` block driver with registered Crucible block callbacks. It does
not alter any upstream block driver or any `crucible-shmem` request before the
plugin registers the callback. The capability key is
`storage.block.typed-result.v1`; block wire ABI version 3 is mandatory and
version 1 is rejected rather than translated through a compatibility path.

## Callback encoding

A successful callback returns its nonnegative response length. `-1` remains the
fail-loud untyped fallback and maps to `EIO`; `-2` remains the pending sentinel.
An exact error is encoded as:

```text
callback_result = -(4096 + linux_errno)
1 <= linux_errno <= 4095
```

The public QEMU plugin header names these constants
`QEMU_PLUGIN_BLK_POLL_ERROR_BASE`, `QEMU_PLUGIN_BLK_POLL_ERROR_MAX`, and
`QEMU_PLUGIN_BLK_POLL_ERROR(errno)`. QEMU accepts only that closed numeric
interval. Values below `-1` outside the typed interval are malformed and return
`EOVERFLOW`; they never alias pending or a successful byte count.

## Result mapping

| Protocol-neutral result | Linux errno | Guest meaning |
| --- | ---: | --- |
| `offline` | `ENOMEDIUM` | Device or medium is unavailable. |
| `read_only` | `EROFS` | A write targeted read-only storage. |
| `invalid_range` | `EINVAL` | The addressed range or request shape is invalid. |
| `busy` | `EBUSY` | The modeled controller or queue is busy. |
| `timeout` | `ETIMEDOUT` | The modeled completion deadline expired. |
| `medium_error` | `EIO` | The medium could not return or persist the data. |
| `integrity_error` | `EILSEQ` | Returned bytes failed modeled integrity validation. |
| `io_error` | `EIO` | A generic modeled I/O failure occurred. |
| `no_space` | `ENOSPC` | Capacity or an allocated storage resource is exhausted. |
| `not_found` | `ENOENT` | The addressed namespace object does not exist. |
| `stale` | `ESTALE` | A retained identity or generation is stale. |

The Rust callback adapter owns this fixed table; QEMU transports the encoded
errno without interpreting the protocol-neutral result. Unknown result bytes,
empty error payloads, and multi-byte error payloads are rejected before the
callback returns to QEMU.

## Ordering, replay, and failure semantics

The typed result is part of the terminal block response at its deterministic
delivery icount. It does not add a second completion, change request ordering,
or consume wall time. Record/replay stores the protocol-neutral result byte and
the block response digest; replay validates both before reproducing the same
callback encoding. A malformed callback value is an infrastructure failure,
not a modeled storage fault.

## Acceptance tests

The focused patch microtest includes the patched QEMU driver source and invokes
its real submit/poll path. It must prove all of the following:

1. every accepted typed callback value becomes the exact negative errno;
2. pending, untyped `EIO`, zero-length success, typed errors, and malformed
   negative values are mutually distinct;
3. oversized successful completions still return `EOVERFLOW`;
4. removing only patch `0060` makes the typed-error assertion fail;
5. stock QEMU exposes neither the Crucible driver nor the new constants; and
6. non-Crucible block drivers and an unregistered callback retain upstream
   behavior.

The aggregate live test additionally boots a guest on the patched driver,
injects each modeled storage result through the real host, shared-memory,
plugin, and QEMU path, and observes the expected errno in the guest. A test
double is not acceptable for that aggregate gate.

## Licensing and source obligations

The patch modifies existing `block/crucible-shmem.c` and
`include/qemu/qemu-plugin.h`; both retain their current GPL-compatible notices.
It creates no QEMU file, so `LICENSES.md` needs no new-file row. The patch commit
requires DCO sign-off and is included in the pinned branch bundle, patch-series
identity, corresponding-source artifact, prefix/drop-one checks, and release
closure.
