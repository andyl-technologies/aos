# 15 - Block discard transport

The terminal GPL-side `0061-crucible-block-discard` QEMU patch extends the block
driver introduced by `0015-crucible-blk-shmem`, and the GPL-2.0-only plugin
transports the resulting real discard request. Patch `0061` applies after
`0060`; the historical `0015` patch and every intervening patch remain
unchanged. Discard is not emulated by issuing a host-side write and does not
bypass the Crucible/QEMU process boundary.

## Capability and ABI

Block wire ABI version 3 adds the closed request operation `discard = 4`. Its
request header carries the exact byte `offset` and positive `count`; it carries
no payload. Versions 1 and 2 are rejected rather than retained as legacy paths.

The QEMU plugin callback ABI adds `QEMU_PLUGIN_BLK_OP_DISCARD = 3`. This value is
local to the QEMU callback surface; the GPL plugin validates it and translates
it to wire operation 4. `QEMU_PLUGIN_BLK_OP_*` values 0 through 2 remain the
existing read, write, and flush callback operations. Get-length is internal to
the host wire codec and has no QEMU callback operation.

## QEMU touch points

`block/crucible-shmem.c` implements `bdrv_co_pdiscard`. It validates the complete
range with the same overflow and device-length checks as a write, submits one
payload-free discard through the registered block callback, waits through the
existing deterministic coroutine polling path, and returns the typed completion
to QEMU. The driver registers this function as `.bdrv_co_pdiscard`.

`include/qemu/qemu-plugin.h` adds only the typed operation constant. Callback
function signatures do not change: for discard, `offset` is the first byte,
`data` is null, and `len` is the requested byte count. A non-null payload,
unrepresentable count, range error, unknown operation, or nonempty successful
response fails loudly.

## Host semantics

The Apache host validates World discard granularity and maximum request bounds
before mutation. Its immutable device contract selects exactly one readback
rule:

| World rule | Device mutation |
| --- | --- |
| `deterministic_zero` | Persist zero bytes through the normal controller/cache/media path. |
| `reads_old_data` | Complete successfully without changing logical bytes. |
| `undefined_recorded` | Persist deterministic device/request-keyed bytes and retain their resulting state in the ordinary storage checkpoint/evidence path. |

Discard reaches the same availability, queue, media, persistence, flush, and
future-read state as other real block requests. Read-only devices reject it.
Unsupported or misaligned discard returns a typed invalid-range result. Flash
erase behavior is layered on this real operation by the separately specified
flash state machine; the transport does not invent flash geometry.

## Determinism, replay, and VMState

The request identity, range, wire digest, execution coordinate, durability
frontiers, persistence graph, and before/after byte digests are ordinary storage
replay evidence. Undefined readback bytes are derived only from immutable base
identity and request fields, never host time or host-device discard behavior.
All resulting host state is already part of the block checkpoint. QEMU retains
only its existing monotone request-ID state, which remains in the block driver's
VMState obligations.

## Required gates

The implementation must include:

1. codec golden vectors and hostile decode cases for ABI version 3;
2. host-device tests for all three readback rules, alignment rejection, rollback,
   save/restore, and media/persistence composition;
3. plugin callback tests proving null-payload/range translation and fail-loud
   rejection;
4. a live patched-QEMU discard test whose guest-visible readback changes and
   whose result turns red if the QEMU patch hunk is reverted;
5. non-sim and unpatched-QEMU inertness checks;
6. `gate:abi-conformance`, `gate:license-boundary`, complete corresponding-source,
   patch-series identity, and source/license inventory checks.

The commit modifying the QEMU patch or GPL plugin carries a DCO sign-off and no
AI attribution.
