# 0062 - Transactional block transport reset

Patch `0062-crucible-block-transport-reset.patch` makes a resolved
`storage.controller_lifecycle.transition_policy` reset observable by a real
guest using the `crucible-shmem` block backend. It replaces the unscoped
request-ID callback ABI with `(epoch, request_id)` identities and adds a
versioned asynchronous event callback. There is no version-3 decoder,
request-ID-only fallback, or silent downgrade.

## Boundary ABI

The submit and poll callbacks take a `u64` epoch before the `u32` request ID.
The event callback returns one complete version-4 `BlockResponse` in a caller-
owned 52-byte buffer. QEMU accepts only these event statuses:

| Status | Exact length | Meaning |
| --- | ---: | --- |
| `transport_reset` | 52 | 20-byte response header plus the closed 32-byte reset payload |
| `duplicate_ignored` | 20 | authenticated notice for an already-completed identity |
| `duplicate_protocol_error` | 21 | authenticated notice plus one closed typed-result byte |

The decoder checks the version, both header reserved bytes, declared payload
length, every enum and boolean, typed result, reset reserved tail, current
epoch, and checked recovery-deadline arithmetic before mutation. Any malformed,
unknown, or out-of-order event fails the backend and wakes all waiters into the
same terminal error path.

The reset payload is:

```text
u64 next_epoch
u64 recovery_nanos
u8  request_id_rule
u8  reenumerate_declared
u8  preserve_duplicate_history
u8  failure_result
u8  unadmitted_policy
u8  queued_policy
u8  executing_policy
u8  resolved_policy
u8  completed_undelivered_policy
u8  preserve_controller_buffer
u8  preserve_volatile_cache
u8  reserved_zero[5]
```

## Transaction and lifecycle semantics

The host publishes the reset event before committing its epoch, recovery, data-
loss, or outstanding-request mutations. A full response ring therefore leaves
the entire pre-reset state intact. The plugin peeks without consuming the ring
entry. QEMU validates and stages the complete event, asks the plugin to commit
the exact peeked entry, and only then applies its already-validated local state.
Plugin commit failure leaves QEMU state unchanged and fails the backend. The
successful commit atomically installs the epoch, allocator rule, recovery
deadline, admission policy, typed failure, and duplicate-history rule before
resuming blocked request coroutines.

`preserve_monotonic` requires the same epoch and leaves the allocator cursor
unchanged. `new_epoch_from_zero` requires exactly `current + 1`, rejects epoch
overflow, and resets the allocator to zero. A request admitted after that point
always carries the installed epoch. The plugin independently authenticates the
same transition and rejects any event identity that has not completed on that
transport.

During recovery, `reject` returns the configured typed Linux errno before
allocating or submitting an identity. `wait_for_recovery` sleeps on QEMU's
virtual clock to the exact deadline and then retries admission. Host-side
authentication additionally rejects any request whose actual arrival icount
maps inside a reject window or carries the wrong epoch.

Outstanding requests receive one of the closed poll dispositions. `fail`
returns the configured typed error. `retry_preserve_id` re-submits the original
operation and buffers with the same epoch and ID, and the plugin consumes a
single completion-derived authorization for that retry. `retry_new_id` waits
for recovery admission and allocates a fresh identity. `drop_completion` keeps
the guest request unresolved without host polling or wall-clock wakeups by
retaining it in virtio-blk's separately migrated, non-restarting request list.
Pause/resume and destination start never resubmit that list. A guest device
reset or device teardown explicitly detaches and frees it without completing
the requests.

Frames already queued in the input ring remain byte-for-byte intact until
normal consumer dequeue. A new-epoch reset retires the old epoch with its exact
queued disposition and typed failure. When each stale frame later reaches the
ring head, the host applies `fail`, `retry_new_id`, or a one-use
`retry_preserve_id` authorization at the current service boundary; it never
schedules a completion in the pre-reset past. Retired epoch rows and live
preserve-ID authorizations have explicit hard bounds and fail the run before
overflow.

When `reenumerate_declared` is set, QEMU invokes the block graph's frontend-
resize notification through the coroutine wrapper. A virtio-blk frontend
consequently raises a configuration interrupt and the guest re-reads the
already-declared geometry; the patch never invents or removes an undeclared
namespace or path.

## Checkpoint and resource contract

The block backend's QEMU VMState version 1 records request epoch, next request
ID, absolute virtual-clock recovery deadline, admission policy, and typed
recovery failure. Its bounded variable buffer contains the plugin's versioned
allocator and exact duplicate-history continuation. Virtio-blk VMState version
3 separately encodes ordinary restartable requests and deliberately dropped
requests; only the former enter the destination restart path. Save and restore
are rejected while a request token, preserve-ID retry authorization, or peeked
event is live, so no native pointer, ring borrow, mutex, callback, or coroutine
is serialized. Restore stages and validates the complete continuation, closed
recovery values, and exact agreement with QEMU's paired allocator fields before
atomically replacing either live state.

The plugin stores completed identities as a contiguous prefix plus bounded
out-of-order gaps per epoch. Both epoch rows and gaps have a hard limit of
1,048,576; exhaustion is a fail-loud run error. Losing duplicate history clears
the complete structure atomically. Preserving it never performs eviction or
probabilistic membership tests.

## Required tests

- a capacity-one shared-memory response ring proves reset state commits only
  after the event is published and uses the delayed publication coordinate;
- all queued, executing, resolved, and completed-undelivered treatments are
  exercised with real request identities;
- retry-preserve proves identical identity and payload, while retry-new proves
  post-recovery allocation;
- every queued reset disposition is exercised with an old frame retained behind
  capacity-one output backpressure;
- reject and wait policies cover the last coordinate before and the exact
  recovery deadline;
- malformed headers, reserved bytes, enums, typed results, lengths, epochs, and
  unknown completed identities fail closed without consuming the frame;
- save/restore preserves allocator, recovery, and duplicate history, rejects
  every live continuation, and leaves prior state unchanged on malformed input;
- a live patched-QEMU guest observes exact errno results and a virtio
  configuration interrupt; removing patch `0062` makes the capability and ABI
  gates fail.

## Licensing and delivery

The patch modifies existing QEMU files only and preserves their per-file
licenses, so `LICENSES.md` gains no created-file row. The patch commit carries
the required DCO sign-off. The patch, deterministic branch commit, bundle,
manifest identity, corresponding-source output, ABI conformance gate, and live
backend gate update atomically.
