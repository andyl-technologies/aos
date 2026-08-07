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
queues the native paused runstate transition, stops the current vCPU, and hands
control back to the main loop. QMP then confirms `running = false` and
`status = paused` without another guest instruction retiring. Save, load, and
continue remain ordinary typed QMP operations.

## API and activation predicate

```c
QEMU_PLUGIN_API
int qemu_plugin_request_vmstop(void);
```

The call is accepted only when all of these conditions hold:

1. `current_cpu` names the vCPU executing the callback;
2. `icount_enabled() == ICOUNT_PRECISE`;
3. the active accelerator is `sim`;
4. TCG is single-threaded round-robin, not MTTCG.

Failure of any predicate returns a nonzero status without calling `vm_stop`.
The return value from `vm_stop(RUN_STATE_PAUSED)` is returned unchanged, so the
plugin cannot mistake a rejected native transition for success. The Rust
plugin resolves the symbol before registering any live callback and rejects
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
   `qemu_plugin_request_vmstop()`.
4. QEMU enters its native paused runstate and the current vCPU stops.
5. Typed QMP `stop` plus `query-status` confirms the paused state.
6. The host clears the shared-memory pause request while QEMU remains stopped.
7. The Apache host captures its network, block, 9p, fault, scheduler, and node
   continuation; QMP saves VMState under the same checkpoint identity.
8. Typed QMP `cont` plus `query-status` confirms the running state.

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
5. arm the shared-memory restore ceiling;
6. load the identity-bound VMState;
7. validate and atomically restore the matching Apache host-I/O continuation;
8. confirm QEMU running through typed QMP continue/status; and
9. restore the already-prevalidated scheduler-facing node continuation before
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

The patch modifies `include/qemu/qemu-plugin.h` and `plugins/api-system.c` only.
It creates no QEMU file, so the created-file license inventory does not gain a
row. Both files retain their existing license scope. The deterministic patch
commit carries the required DCO sign-off and is included in the matching
corresponding-source bundle.

## Required tests and gates

- The focused C microtest calls the actual patched export, proves the native
  `RUN_STATE_PAUSED` request, verifies rejection without a current vCPU, under
  disabled/non-precise icount, under MTTCG, and outside `sim`, and proves the
  exact native failure code is propagated.
- The stock negative control proves the symbol is absent before the patch; the
  drop-one and patch-prefix gates attribute the symbol only to patch `0063`.
- Plugin unit tests prove a pause publication precedes the stop request and a
  nonzero status becomes a typed fail-loud callback error.
- The live diskless checkpoint gate proves capture, process destruction, fresh
  process restore, and deterministic continuation.
- The live dirty-cache gate performs the same process-destruction restore while
  a real virtio block mutation has acknowledged but non-durable continuation
  state.
- `gate:patch-microtests`, `gate:abi-conformance`,
  `gate:license-boundary`, patch regeneration, patched-QEMU build, exact
  snapshot/restore, and complete corresponding-source checks all consume the
  new patch identity.

Removing patch `0063` must make plugin capability admission, the focused
microtest, the drop-one gate, and both live exact-checkpoint gates fail closed.
