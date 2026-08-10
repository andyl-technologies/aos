# 0063 - Exact plugin-boundary VM stop

Patch `0063-crucible-plugin-vmstop.patch` adds the one in-process operation
needed to hand a boundary published by the GPL-side Crucible plugin to QEMU's
native machine-control state. It exports `qemu_plugin_request_vmstop()` and
implements that export by calling `vm_stop(RUN_STATE_PAUSED)` from the current
vCPU thread. The patch does not add a second snapshot mechanism, a host-side
QEMU callback, or a shared-memory representation of QEMU state.

## Why the patch is required

The shared-memory pause request can make the plugin publish an exact node
instruction count, an exact idle wake coordinate, and an inactive-device
observation. Merely returning from the idle callback or setting
`CPUState::exit_request` does not change QEMU's runstate. A subsequent QMP
`stop` can therefore wait behind the same vCPU execution path whose boundary it
is meant to preserve.

The new export uses QEMU's existing vCPU-thread `vm_stop()` path. That path
queues the native paused runstate transition and stops the current vCPU. A
Crucible-specific round-robin fence then prevents the shared TCG execution
thread from selecting any vCPU again. While fenced, the thread still services
host work for every vCPU so QEMU can convert each `stop` request into its
`stopped` acknowledgement; it never dispatches guest code. The fence records
separate `admitted` and `stopped` states. A premature QMP `cont` is rejected
before it can reset block or block-job I/O status while the main loop has not
yet consumed the stop. Only a later successful `cont` from `stopped` clears the
fence immediately before QEMU resumes the vCPUs. QMP confirms
`running = false` and `status = paused`; save, load, and continue remain
ordinary typed QMP operations.

## API and activation predicate

```c
QEMU_PLUGIN_API
int qemu_plugin_request_vmstop(void);
```

The call is accepted only when all of these conditions hold:

1. `current_cpu` identifies the active shared RR vCPU-thread context;
2. the callback was entered by an exact boundary owned by the sim RR loop;
3. `icount_enabled() == ICOUNT_PRECISE`;
4. the active accelerator is `sim`;
5. TCG is single-threaded round-robin, not MTTCG; and
6. no prior admitted stop is waiting for a stop/resume cycle to complete.

The exact contexts are the post-`tcg_cpu_exec` callback, sim shared-memory
publish and maximum-advance callbacks, sim observer notification and
maximum-advance callbacks, and sim vCPU idle/resume callbacks. Instruction,
memory, syscall, translation, and arbitrary plugin callbacks are not exact
contexts and are rejected even if they happen to run on a vCPU thread. This
prevents a callback in the middle of a translated block from claiming that the
block's suffix cannot execute.

Failure of the execution-mode or callback-context predicates returns `-EPERM`
without calling `vm_stop`. A duplicate admission returns `-EALREADY`. A zero
return reports that the asynchronous vCPU-thread request was admitted; it does
not claim that QEMU has already completed the transition or flushed block
devices. `query-status` is the completion and failure channel. The Rust plugin
resolves the symbol before registering any live callback and rejects
installation if it is absent.

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
2. At a vCPU callback boundary, the plugin validates the scheduler ceiling and
   publishes the exact current icount, `idle_wake_icount == current_icount`,
   inactive device state, and a fresh publication generation.
3. With release-published boundary state already visible, the plugin calls
   `qemu_plugin_request_vmstop()` from that scheduler-owned callback.
4. The `admitted` state closes the RR-global dispatch fence before `vm_stop()`
   queues the native paused transition and exits the current vCPU.
5. The main loop enters native paused runstate, flushes block devices, records
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
controlled by QEMU and QMP; shared memory contains only the existing fixed-width
pause request and exact observation fields. The Apache host never links QEMU,
includes a QEMU header, or calls the export. Only the GPL-2.0-only plugin
resolves and invokes it inside the QEMU process.

The patch modifies `include/qemu/qemu-plugin.h`, `include/qemu/plugin.h`,
`plugins/api-system.c`, `accel/tcg/tcg-accel-ops-sim-shmem.c`,
`accel/tcg/tcg-accel-ops-rr.c`, `system/cpus.c`, and `monitor/qmp-cmds.c`. It
creates no QEMU file, so the created-file license inventory does not gain a row.
Every file retains its existing license scope. The deterministic patch commit
carries the required DCO sign-off and is included in the matching corresponding-source
bundle.

## Required tests and gates

- The focused C microtest calls the actual patched export, proves native pause
  admission, verifies the global pending fence and duplicate rejection, proves
  retention of an asynchronous native flush error, proves rejection outside a
  scheduler-owned exact callback, and verifies rejection
  without a current vCPU, under disabled/non-precise icount, under MTTCG, and
  outside `sim`.
- The stock negative control proves the symbol is absent before the patch; the
  drop-one and patch-prefix gates attribute the symbol only to patch `0063`.
- Plugin unit tests prove a pause publication precedes the stop request and a
  nonzero status becomes a typed fail-loud callback error.
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
