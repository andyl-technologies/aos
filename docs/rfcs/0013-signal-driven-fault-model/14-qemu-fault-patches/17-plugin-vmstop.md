# 0063 - Exact plugin-boundary VM stop

Patch `0063-crucible-plugin-vmstop.patch` adds the one in-process operation
needed to hand a boundary published by the GPL-side Crucible plugin to QEMU's
native machine-control state. It exports `qemu_plugin_request_vmstop()`;
follow-up patch `0073-crucible-device-wait-vmstop.patch` distinguishes the
drained main-loop control boundary from device-completion contexts. The patch
stack does not add a second snapshot mechanism, a host-side QEMU callback, or
a shared-memory representation of QEMU state.

## Why the patch is required

The shared-memory pause request can make the plugin publish an exact node
instruction count, an exact idle wake coordinate, and an inactive-device
observation. Merely returning from the idle callback or setting
`CPUState::exit_request` does not change QEMU's runstate. A subsequent QMP
`stop` can therefore wait behind the same vCPU execution path whose boundary it
is meant to preserve.

The new export selects the stop mechanism from the exact callback context. A
drained control wake already runs in the main loop outside device coroutines,
so it calls `vm_stop()` synchronously and cannot dispatch another TCG slice.
Device-completion and vCPU callbacks use the asynchronous half of QEMU's
vCPU-thread `vm_stop()` path: they queue the native paused transition and stop
the current vCPU when one exists. A Crucible-specific round-robin fence then
prevents the shared TCG execution thread from selecting any vCPU again.
While fenced, the thread still services host work for every vCPU so QEMU can
convert each `stop` request into its `stopped` acknowledgement; it never
dispatches guest code. The fence records separate `admitted` and `stopped`
states. A premature QMP `cont` is rejected before it can reset block or
block-job I/O status while the main loop has not yet consumed the stop. Only a
later successful `cont` from `stopped` clears the fence immediately before QEMU
resumes the vCPUs. QMP confirms
`running = false` and `status = paused`; save, load, and continue remain
ordinary typed QMP operations.

## API and activation predicate

```c
QEMU_PLUGIN_API
int qemu_plugin_request_vmstop(void);
```

The call is accepted only when all of these conditions hold:

1. the callback was entered by an exact boundary owned by the sim RR loop;
2. `icount_enabled() == ICOUNT_PRECISE`;
3. the active accelerator is `sim`;
4. TCG is single-threaded round-robin, not MTTCG; and
5. no prior admitted stop is waiting for a stop/resume cycle to complete.

The exact contexts are the post-`tcg_cpu_exec` callback, sim shared-memory
publish and maximum-advance callbacks, sim observer notification and
maximum-advance callbacks, sim vCPU idle/resume callbacks, the dedicated
drained-control callback, and block, 9p, or accelerator completion callbacks
nested inside those sim dispatch scopes.
Instruction, memory, syscall, translation, and arbitrary plugin or device
callbacks are not exact contexts and are rejected even if they happen to run
on a vCPU thread. This prevents a callback in the middle of a translated block
from claiming that the block's suffix cannot execute.

Failure of the execution-mode or callback-context predicates returns `-EPERM`
without changing runstate. A duplicate admission returns `-EALREADY`. A zero
return reports that the transition was admitted; it does not replace
`query-status` as the authoritative completion and failure channel. The Rust plugin
resolves the symbol before registering any live callback and rejects
installation if it is absent. Because the shared-memory pause request is
level-triggered, more than one eligible exact callback can observe it before
the main loop consumes the first request. The plugin treats `-EALREADY` as an
idempotent successful handoff: QEMU has already fenced and queued the one stop
needed for that pause generation. Every other nonzero result remains fatal.

The patch series does not expose the earlier void
`qemu_plugin_crucible_pause_vm()` helper. That unvalidated operation discarded
the native stop result and could report no distinction between an accepted
boundary and a rejected transition. All GPL-side callers use the typed export;
a nonzero result is either returned as a typed callback error or requests a
fail-loud QEMU shutdown.

## Capture state machine

The host and QEMU processes execute this ordered transaction:

1. The host sets the versioned shared-memory pause request and rings the
   existing eventfd.
2. At a scheduler callback boundary, or at the completion callback that clears
   the final active-device marker, the plugin validates the scheduler ceiling
   and publishes the exact current icount,
   `idle_wake_icount == current_icount`, inactive device state, and a fresh
   publication generation.
3. With release-published boundary state already visible, the plugin calls
   `qemu_plugin_request_vmstop()` from that exact callback.
4. The `admitted` state closes the RR-global dispatch fence. A drained control
   wake completes `vm_stop()` synchronously; a device-completion or vCPU
   callback queues the transition and exits the current vCPU when present.
5. QEMU enters native paused runstate, flushes block devices, records
   the exact flush result, and advances the fence to `stopped`. A typed QMP
   `stop` returns either that retained asynchronous flush failure or a failure
   from its own confirming flush. A retained failure also makes `cont` fail
   before any resume side effect. `query-status` confirms the paused transition.
6. The host clears the shared-memory pause request while QEMU remains stopped.
7. The Apache host captures its network, block, 9p, fault, scheduler, and node
   continuation; QMP saves VMState under the same checkpoint identity.
8. A successful QMP `cont` clears the fence immediately before QEMU resumes
   vCPUs; `query-status` then confirms the running state.

No wake thread runs alongside the blocking QMP command. No futex remains held
by the plugin after it publishes the boundary. Any failed stop, pause release,
host capture, VMState save, or continue follows a typed cleanup path; a QMP
timeout terminates the unusable child rather than exposing a partly resumed
node.

## Restore state machine

A fresh process is primed through the ordinary deterministic boot barrier, then
uses the same stop handoff:

1. prevalidate load authorization, checkpoint identity, and node-continuation
   invariants;
2. request and observe a fresh exact plugin boundary;
3. confirm QEMU's native paused state through typed QMP;
4. clear the plugin pause while QEMU remains stopped;
5. submit an ABI-v8 logical/raw calibration transaction and require its matching
   request-ID acknowledgement and exact raw-coordinate result;
6. arm the shared-memory restore ceiling at that calibrated raw coordinate;
7. load the identity-bound VMState;
8. validate and atomically restore the matching Apache host-I/O continuation;
9. confirm QEMU running through typed QMP continue/status; and
10. restore the already-prevalidated scheduler-facing node continuation before
    exposing the assembled node.

There is no load-while-running path, request-ID-only fallback, deprecated
barrier command, or eventfd-pulsing workaround. A primary restore failure is
reported together with an independent continue failure when both occur.

## State, migration, and process boundary

The export adds no migratable fields. Native QEMU runstate is intentionally
controlled by QEMU and QMP; ABI v14 shared memory contains only fixed-width
pause, observation, and `control_boundary_ack` fields. The acknowledgement
token replaces reserved node-slot padding without changing the slot size; v13
is rejected outright. The Apache host never links QEMU,
includes a QEMU header, or calls the export. Only the GPL-2.0-only plugin
resolves and invokes it inside the QEMU process.

The patch stack modifies `include/qemu/qemu-plugin.h`, `include/qemu/plugin.h`,
`plugins/api-system.c`, `block/crucible-shmem.c`,
`accel/tcg/tcg-accel-ops-sim-shmem.c`,
`accel/tcg/tcg-accel-ops-rr.c`, `system/cpus.c`, and `monitor/qmp-cmds.c`. It
creates no QEMU file, so the created-file license inventory does not gain a row.
Every file retains its existing license scope. The deterministic patch commit
carries the required DCO sign-off and is included in the matching corresponding-source
bundle.

Patch `0073` gives every scheduler-owned or device-completion exact callback a
safe native-stop path. It adds a required
`qemu_plugin_register_control_boundary_cb()` surface distinct from vCPU resume:
waking QEMU's main loop does not mean a halted vCPU became runnable, so the
control callback may acknowledge pause or shutdown but must not mutate halt
tracking. The wake-fd handler schedules a coalesced two-pass callback after the
pipe is drained. If an idle-time advance is pending, the callback relinquishes
its coalescing token; idle-advance completion schedules a fresh callback after
the plugin commits logical time and QEMU clears the pending barrier. Those
placements acknowledge a pause without executing another guest instruction,
including one that arrived during an idle jump. Admission relies on QEMU's
maintained exact-boundary depth rather than `current_cpu`, which is legitimately
null in some sim publication and completion callbacks. Arbitrary plugin and
device callbacks remain rejected because they never enter that exact scope.
For each drained-control callback, the host changes ABI-v14
`control_boundary_ack` from an odd acknowledgement to its even successor, wakes
the plugin's futex, and rings the eventfd. An idle callback returns to QEMU's
main loop without authorizing time, while a resume callback that still sees the
even request preserves halt and idle state. QEMU coalesces duplicate requests,
runs a two-pass bottom-half barrier, and defers an overlapping request until an
idle-time advance commits. The plugin republishes the exact callback coordinate
before release-storing the odd successor. At a clamped ceiling the publication
is exact idle and retains a previously published future deadline; below the
ceiling it preserves the prior vCPU classification. The host accepts the
immediate or a later odd acknowledgement in wrapping serial order and requires
idle, exact-coordinate, no-device-I/O state before completing a clamp.

The Rust plugin deliberately does not acknowledge checkpoint pause from the
`crucible-shmem` block-wait callback while device I/O remains active. That
callback is nested inside an in-flight block coroutine, and QEMU must finish
the admitted operation before it can complete native stop. Requesting stop
before completion would create a circular wait: native stop drains the
operation whose callback is waiting for native stop. Block poll, 9p poll or
burst completion, and accelerator poll first finish the work already authorized
by the scheduler. The callback that clears the final device-active marker then
publishes the quiescent pause boundary and admits the stop.

Admission from a device-completion or vCPU callback never calls `vm_stop()`.
From a completion callback where `current_cpu` is null, `vm_stop()` would
synchronously drain devices and wait on the callback that invoked it. Those
contexts perform the lock-protected `qemu_system_vmstop_request_prepare()` and
`qemu_system_vmstop_request(RUN_STATE_PAUSED)` pair, then call
`cpu_stop_current()` when a current vCPU exists. The drained-control callback is
different: it runs directly in the main-loop event handler after the wake fd is
empty and outside every device coroutine. It calls `vm_stop()` synchronously so
the runstate changes before the main loop can dispatch another TCG slice. QMP
remains the authoritative completion channel for both paths.

## Required tests and gates

- The focused C microtest calls the actual patched export, proves native pause
  admission, verifies the global pending fence and duplicate rejection, proves
  retention of an asynchronous native flush error, proves rejection outside a
  scheduler-owned exact callback, proves admission from an exact callback with
  no current vCPU, and verifies rejection under disabled/non-precise icount,
  under MTTCG, and outside `sim`.
- The stock negative control proves the symbol is absent before the patch; the
  drop-one and patch-prefix gates attribute the symbol only to patch `0063`.
- Plugin unit tests prove a pause publication precedes the stop request and a
  nonzero status becomes a typed fail-loud callback error.
- The patch microtest proves synchronous stop at a drained control boundary,
  nonblocking main-loop admission from other exact scopes without requiring
  `current_cpu`, retention of the admission fence, rejection outside an exact
  scope, coalescing of duplicate control requests, the two-pass device-BH
  barrier, and deferral behind an overlapping idle-time advance.
- The live diskless checkpoint gate uses at least two vCPUs and proves capture,
  process destruction, fresh-process restore, an idle-clock calibration replay,
  and an identical deterministic continuation suffix without another vCPU
  crossing the admitted boundary.
- The live dirty-cache gate performs the same process-destruction restore while
  a real virtio block mutation has acknowledged but non-durable continuation
  state.
- `gate:patch-microtests`, `gate:abi-conformance`,
  `gate:license-boundary`, patch regeneration, patched-QEMU build, exact
  snapshot/restore, and complete corresponding-source checks all consume the
  new patch identity.

Removing patch `0063` must make plugin capability admission, the focused
microtest, the drop-one gate, and both live exact-checkpoint gates fail closed.
