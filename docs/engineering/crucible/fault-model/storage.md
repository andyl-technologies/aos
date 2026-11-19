# Storage and 9p fault adapter

Persistence faults are not generic completion errors. A lost write that the
guest saw succeed, a flush that lied, and a sector that went bad after the
write was durable are different states with different future reads. The
storage adapter therefore models durability layers explicitly and keeps the
block and 9p protocols typed.

Sources: effect parameters in
[`storage_effect.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/storage_effect.rs);
world policies in
[`world_storage_policy.rs`](../../../../crates/crucible/crucible-engine/src/model/world_storage_policy.rs)
and [`world_faults/storage.rs`](../../../../crates/crucible/crucible-engine/src/model/world_faults/storage.rs);
production coordination in
[`crucible-daemon/src/vm_lifecycle/storage_faults.rs`](../../../../crates/crucible/crucible-daemon/src/vm_lifecycle/storage_faults.rs);
directive resolution in
[`crucible-qemu-host/src/storage_fault_resolver.rs`](../../../../crates/crucible/crucible-qemu-host/src/storage_fault_resolver.rs);
device models in
[`crucible-device/src/block/`](../../../../crates/crucible/crucible-device/src/block/) and
[`crucible-device/src/ninep/`](../../../../crates/crucible/crucible-device/src/ninep/).

## Division of responsibility

Signal evaluation and keyed hazard decisions happen in the engine. The block
resolver consumes only committed, typed `ResolvedBindingAction` values for one
exact request and translates them into a `ResolvedBlockFaultDirective`; it never
evaluates signals, consults host time, or substitutes a different behavior.
Coordinators fail closed after admission and evaluate only authenticated
opportunities. Named policies (queue, cache, transition, array, typed result)
are declarations in a closed storage-policy registry resolved at admission and
retained by content identity in evidence; behavior is never selected by
comparing ID strings or reading host files.

## Durability layers

```text
guest request/completion protocol
  -> admission and request queue
  -> controller / namespace / path state
  -> volatile write cache and ordering frontier
  -> durable logical block map
  -> media geometry, health, wear, flash state
```

Guest completion, controller acceptance, volatile-cache acceptance, and durable
persistence are distinct events. A device declares its completion stage with
`WorldCompletionDurability` (`controller_accepted`, `volatile_cache_accepted`,
or `durable`); success never implicitly means durable. Writes are split
deterministically at atomic-write boundaries into fragments, each with an
intended digest and controller, cache, and durable sequences. No host
filesystem atomicity is assumed. Reads resolve against a canonical interval
map, and mixed-version reads arise only from explicit torn, misdirected, or
reordered-persistence effects.

## Service and queues

`storage.service` is real pre-execution service, not completion latency: a
request does not touch device state until every contributing constraint
releases it. The rule (byte rate, optional IOPS, queue depth) is sampled
atomically at queue admission and retained with the request, so a later signal
change affects only later admissions. Each contributor is an independent
non-preemptive server; the request runs at the latest release. Byte and
operation deadlines use checked cumulative integer ledgers per busy epoch to
avoid rounding drift. Overflow at any contributor rejects the whole admission
with the protocol-neutral `busy` result; nothing is silently retried.

`StoragePolicyQueueDiscipline` is `fifo`, `strict_priority`, or
`weighted_round_robin`; ties break by admission coordinate and request
sequence, and active requests are never preempted. `storage.latency` adds
completion delay separately.

## Cache, persistence order, and write dispositions

The volatile cache is bounded by bytes and entries with eviction `fifo`, `lru`,
or `writeback_sequence`; dirty eviction either persists or fails per policy and
never silently discards data. Controller-accepted entries occupy a separate
bounded buffer and loss domain.

`storage.volatile_cache_loss` is an impulse with selector `all`,
`after_sequence`, `range_intersection`, or a keyed bounded subset, and kind
`power_loss` or `protection_failure`. Resolution records the pre-loss
entry-set digest; locked replay requires that digest before removing anything.
Reads after loss see the prior durable version.

Persistence is a finite dependency DAG (fragment order, FUA, flush frontiers,
array ordering, and explicit `storage.persistence_order` effects); a reorder
cannot create a cycle.

`storage.write_disposition` is one of:

| Kind | Semantics |
| --- | --- |
| `apply` | Fragments follow normal cache and persistence policy. |
| `lost` | Selected fragments never reach cache or media; guest status is independent. |
| `torn` | Selected atomic fragments apply; others keep their prior version. |
| `misdirected` | Fragments land in an explicit destination device and range. |

A misdirection's destination range is a bounded transfer window, validated for
alignment and capacity at admission; the adapter never truncates, wraps, or
invents offsets. Cross-device misdirection commits both devices together or
neither.

## Flush

A flush captures the frontier admitted before it. `storage.flush_disposition`
is `honest` (completes when the frontier is durable), `error`, `stall` (no
completion until recovery or timeout; recovery persists exactly the captured
frontier), or `lie` (reports success while the durable frontier does not
advance). A lie records both the reported and the actual frontier; later power
loss applies to the actual state.

## Controllers, media, flash, and arrays

- `storage.availability` is `online`, `offline`, `read_only`, or `degraded`.
  `storage.reported_capacity` changes the guest-visible length with an explicit
  policy for truncated and expanded ranges.
- `storage.controller_lifecycle` performs `reset`, `reconnect`, or `enumerate`
  transitions. Their transition policy fixes the treatment of unadmitted,
  queued, executing, resolved, and completed-but-undelivered operations,
  controller and cache retention, and whether request IDs stay monotonic or
  start a new epoch (identity is then `(epoch, request_id)`).
- `storage.media_range` overlays canonical non-overlapping intervals in state
  `bad`, `latent`, `poisoned`, or `read_only`. Threshold counters advance at
  media opportunities, not at guest retries that fail earlier.
- `storage.flash_state` tracks per-erase-block wear, retention, and read
  disturb; it never invents an FTL that the world did not declare.
- `storage.array_state` atomically replaces an array's complete member, path,
  selection, rebuild, and consistency policy; deactivation restores the
  declared baseline. Layouts are `mirror`, `stripe`, `single_parity`, and
  `dual_parity`. A logical array device can never also be a backing member.
- `storage.read_transform` applies bit flips, stale versions, or misdirected
  reads to returned bytes only; it does not mutate media.
- `storage.duplicate_completion` and `storage.completion_reorder` act at the
  guest transport boundary; a duplicate configured for reset executes the live
  transport reset transition.

## Block fault protocol

Guest-visible block faults travel over the block shared-memory wire protocol,
version 4 (`BLOCK_ABI_VERSION` in
[`crucible-device/src/block/codec.rs`](../../../../crates/crucible/crucible-device/src/block/codec.rs),
mirrored independently by `BLOCK_WIRE_VERSION` in the GPL plugin's
[`block_io.rs`](../../../../crates/crucible/crucible-qemu-plugin/src/block_io.rs)
and `CRUCIBLE_BLOCK_WIRE_VERSION` in QEMU's `block/crucible-shmem.c`). No
older version is decoded. Requests have a 28-byte header and responses a
20-byte header. Request identity is the pair `(epoch, request_id)`; the QEMU
submit and poll callbacks take a `u64` epoch before the `u32` request ID.

### Typed errors

An error response carries exactly one result byte. The host
(`BlockErrorCode` in `crucible-device/src/block/codec/types.rs`) and the plugin
(`BlockResponseErrorCode` in `crucible-qemu-plugin/src/block_io/wire.rs`)
define the same closed table, and the plugin maps each value to the Linux errno
the guest sees:

| Byte | Result | Guest errno |
| ---: | --- | --- |
| 1 | `offline` | `ENOMEDIUM` (123) |
| 2 | `read_only` | `EROFS` (30) |
| 3 | `invalid_range` | `EINVAL` (22) |
| 4 | `busy` | `EBUSY` (16) |
| 5 | `timeout` | `ETIMEDOUT` (110) |
| 6 | `medium_error` | `EIO` (5) |
| 7 | `integrity_error` | `EILSEQ` (84) |
| 8 | `io_error` | `EIO` (5) |
| 9 | `no_space` | `ENOSPC` (28) |
| 10 | `not_found` | `ENOENT` (2) |
| 11 | `stale` | `ESTALE` (116) |

Unknown bytes and empty or multi-byte error payloads are rejected before the
callback returns. The poll callback encodes an exact errno as
`-(QEMU_PLUGIN_BLK_POLL_ERROR_BASE + errno)` with base 4096 and errno in
1..=4095 (`QEMU_PLUGIN_BLK_POLL_ERROR(errno)`). `-1` remains the untyped
`EIO` fallback and `-2` is `QEMU_PLUGIN_BLK_POLL_PENDING`; any other negative
value or an oversized length returns `EOVERFLOW`. QEMU transports the errno
without interpreting the result, which is part of the terminal response at its
deterministic delivery coordinate: it adds no completion and consumes no wall
time.

### Discard

Discard is wire operation 4 (after read 0, write 1, flush 2, and the host-only
get-length 3) and carries an exact byte offset and positive count with no
payload. On the QEMU side the driver implements `.bdrv_co_pdiscard` and
submits `QEMU_PLUGIN_BLK_OP_DISCARD` (3), which the plugin validates and
translates to wire operation 4; a non-null payload, range error, or nonempty
successful response fails loudly. Discard is a real block request: it passes
the same availability, queue, media, persistence, and flush paths as other
requests, read-only devices reject it, and misaligned or unsupported discard
returns `invalid_range`. The device's declared `WorldDiscardSemantics` selects
the readback rule:

| Rule | Device mutation |
| --- | --- |
| `deterministic_zero` | Persist zero bytes through the normal controller, cache, and media path. |
| `reads_old_data` | Complete without changing logical bytes. |
| `undefined_recorded` | Persist bytes derived from device and request identity, retained in checkpoint and evidence. |

### Transport reset

A `storage.controller_lifecycle` reset becomes guest-observable through an
asynchronous event callback that returns one complete response in a
caller-owned 52-byte buffer. Response statuses are `ok` (0), `error` (1),
`transport_reset` (2), `duplicate_ignored` (3), `duplicate_protocol_error` (4),
`retry_preserve_id` (5), `retry_new_id` (6), and `drop_completion` (7). Events
accept only:

| Event status | Length | Contents |
| --- | ---: | --- |
| `transport_reset` | 52 | Response header plus the 32-byte reset payload. |
| `duplicate_ignored` | 20 | Authenticated notice for an already-completed identity. |
| `duplicate_protocol_error` | 21 | Notice plus one typed-result byte. |

The reset payload (`BlockTransportReset`, little-endian) is:

```text
u64 next_epoch
u64 recovery_nanos
u8  request_ids            0 preserve_monotonic, 1 new_epoch_from_zero
u8  reenumerate_declared   bool
u8  preserve_duplicate_history
u8  failure_result         typed error byte
u8  unadmitted             0 reject, 1 wait_for_recovery
u8  queued                 fail | retry_preserve_id | retry_new_id
u8  executing              fail | retry_preserve_id | retry_new_id
u8  resolved               complete | fail | retry_preserve_id | retry_new_id
u8  completed_undelivered  ... | drop_completion
u8  preserve_controller_buffer
u8  preserve_volatile_cache
u8  reserved_zero[5]
```

Every enum, boolean, reserved byte, the current epoch, and the recovery
deadline arithmetic are validated before mutation; a malformed or out-of-order
event fails the backend. `preserve_monotonic` keeps the epoch and request
cursor; `new_epoch_from_zero` requires exactly the next epoch and restarts IDs
at zero. The host publishes the event before committing its own reset
mutations, and QEMU stages the event, has the plugin commit the exact peeked
ring entry, and only then installs epoch, recovery deadline, admission policy,
and typed failure. During recovery, `reject` returns the configured errno and
`wait_for_recovery` sleeps on QEMU's virtual clock to the deadline.
`drop_completion` leaves the guest request unresolved without host polling.
When `reenumerate_declared` is set, QEMU raises the frontend resize
notification so the guest re-reads the already-declared geometry.

## 9p

The 9p adapter models typed requests and results, fid and session state,
namespace objects, data versions, and visibility frontiers; it does not
simulate a host filesystem. Request identity is
`(request coordinate, transport sequence, tag, frame digest)`, so repeated
identical frames stay distinct, and a malformed body remains an opportunity
that reaches the server's deterministic error. Production execution needs an
explicit directive for every request, including the fault-free one.

`ninep.result` is `errno` (a positive Linux errno returned as `Rlerror` without
mutating state), `stale`, or `misdirected` (both name an exact object and apply
only to object-returning operations). Errno dominates object transforms.
`ninep.visibility` separates committed updates from per-session or global
visible frontiers; frontiers advance only over a contiguous ready prefix, and
release deadlines derive once from the resolved action, never from host polls.

Each host service call prepares the complete transaction (evaluator
continuation, journal, device queues, directives, fids, sessions, visibility)
on a clone and then performs exactly one shared-ring transition: publishing
already-authorized replies or consuming one pinned request. Any earlier failure
restores host-private state exactly; the live rings are never rewound outside
the quiesced checkpoint protocol.

## Replay evidence

Storage effect records retain the applicable request, fragment, range, and
version IDs; queue, cache, and durable frontiers; dependency-graph digest;
guest status; intended, cached, durable, returned, and transformed byte
digests; controller, path, and array versions; media and flash counters; and
the exact before-state required by destructive locked replay. Locked replay
verifies everything that made a persistence or media decision eligible before
applying it.
