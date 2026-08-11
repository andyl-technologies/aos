# Patch 0056 — `crucible-node-lifecycle-faults`

## Purpose

Implements live QEMU node crash, controlled power loss, deterministic reset/power
cycle, hang, boot failure, intermittent reset, and recovery transitions with
explicit volatile/device-state policies.

## Capability and dependencies

- Provides `qemu.node.lifecycle.v1` and `qemu.node.hang.v1` on both architectures.
- Depends on 0047–0055, safe boundary, deterministic machine reset, VM process
  supervision protocol, and device co-sim quiescence.

## Lifecycle states

```text
created -> initializing -> booting -> running <-> paused
                |           |          |
                v           v          v
              failed <--- boot_failed  hung
                                        |
running -> resetting -> booting          +-> recovering -> running
running -> powering_off -> powered_off -> power_on -> booting
running -> crashing -> crashed -> supervised_restart -> booting
```

Every transition has an exact boundary, reason/effect ID, downtime or recovery
event, and state treatment. `crashed` is a controlled QEMU process termination
after publishing terminal evidence; `hung` leaves the process alive and
responsive to the fault control/save diagnostic channel but retires no guest
instructions or device work covered by the selected hang scope.

## Closed transition and hang payloads

A lifecycle command carries exactly the transition
`boot/crash/reset/power_off/power_cycle/permanent_failure`, virtual downtime,
boot policy, volatile-state policy, and device-state policy. `preserve/clear`
applies to RAM plus CPU/register, interrupt, timer, and guest-clock volatile
state; device state additionally permits `device_reset`, which invokes each
realized device's production reset method. The command precondition binds the
expected lifecycle/state digest. Network, storage, and other external-process
state is controlled by separate same-coordinate bindings to those production
adapters; QEMU neither encodes nor silently chooses their policies.

A hang command carries exactly `node`, sorted numeric `vcpus`, or one realized
device scope; a recovery-event identity; and either a disabled watchdog or
`transition_after { timeout_nanos, transition, downtime_nanos, boot_policy,
volatile_state_policy, device_state_policy }`. The watchdog's nested lifecycle
plan obeys the same closed cross-field rules as a direct lifecycle command;
there are no default state-loss policies. There are no restart-source, queue,
clock, boot-stage, or other opaque policy IDs.

## Reset and power semantics

- `reset` invokes deterministic architecture/machine reset after applying the
  explicit volatile and device policies. `preserve` and `clear` therefore make
  warm-versus-cold behavior explicit without a second transition name.
- `power_off` stops execution/devices after applying declared volatile-loss and
  queue treatment; no virtual timers progress for the powered-off node unless a
  separate external power-on event exists.
- `power_cycle` is power-off followed by cold reset after exact downtime.
- architecture triple-fault/reset routes through this same transition contract
  and records its architecture cause.

The Apache host applies network/storage external-device state policies through
their adapters at the same canonical boundary. QEMU publishes its transition
result before the host commits the cross-domain combined transition; mismatch is
fatal and recovered only by restoring the pre-boundary checkpoint.

## Boot failure

`immediate` releases the realized machine without a ready marker.
`require_ready` names one realized marker, a positive bounded maximum-attempt
count, exact virtual retry delay, and terminal `crash`, `power_off`, or
`permanent_failure` transition. The capability manifest may expose native
pre-release, reset-vector, firmware-handoff, and guest ready-point markers; an
unmanifested marker is rejected. Repeated/intermittent reset behavior is a
temporal signal producing repeated lifecycle commands, not hidden retry logic.

## Hang scopes

Selected-vCPU hang stops exactly the sorted numeric vCPU set while allowing
other vCPUs and modeled external device progress; `node` hang stops vCPUs and
device callback/service progress after safe quiescence; device hang freezes one
declared realized device.
Control, diagnostic, and recovery command processing remains available. A hang
cannot be implemented by blocking a host thread or deadlocking QEMU.

## Evidence and VMState

Evidence includes old/new lifecycle state, QMP/run state, process generation,
reset/power reason, every state-treatment policy and affected-state digest,
terminal/pre-restart fingerprints, process exit status, deterministic
realization identity, and ready-marker result. Patch 0059 serializes nonterminal lifecycle,
hang/recovery, ready-marker wait, retry count, and reset policy. A crashed
process is reconstructed by the host from the same authenticated deterministic
realization and verified state.

## Live microtests

1. Exercise preserved/cleared reset, power off/on/cycle, controlled crash/restart, vCPU/
   node/device hang, boot failures at every stage, and intermittent sequences.
2. Verify each volatile/device state policy with sentinel RAM, register,
   interrupt, timer, clock, and device state; verify separate same-coordinate
   host network/storage bindings for external state.
3. Trigger x86 triple fault and corresponding AArch64 fatal reset policy and
   verify the common lifecycle path.
4. Save/restore every nonterminal state; reproduce crashed restart from the
   same deterministic realization.
5. Verify control remains responsive during hang and no host blocking models it.
6. Revert patch and fail live gate; prove non-sim reset/power behavior unchanged.

## Licensing checklist

Machine/reset/run-state changes are GPL-side and inert outside sim-fault mode.
The host supervisor communicates only via public lifecycle protocol and QMP as
already authorized; it does not link QEMU internals. Preserve notices, inventory
new files, DCO-sign, and ship microtests/catalog/corresponding source.

- **[QFP-LIFE-1]** Every lifecycle transition MUST define every mutable-state
  domain's preserve/reset/lose treatment; unspecified state is a schema error.
- **[QFP-LIFE-2]** Hang MUST be a deterministic schedulable state, never a host
  deadlock or sleep.
