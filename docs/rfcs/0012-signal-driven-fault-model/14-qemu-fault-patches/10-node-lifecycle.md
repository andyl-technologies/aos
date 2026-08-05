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

## Transition payload

Fields: transition, scope (`cpu`, `node`, selected device domains), downtime or
recovery event, restart source (`genesis`, named checkpoint, current reset
vector), RAM policy, CPU/register policy, device policy, volatile storage/network
queue policy, clock policy, pending interrupt/timer policy, boot-failure stage,
and expected lifecycle/state digest. Every policy field is required.

## Reset and power semantics

- `warm_reset` invokes deterministic architecture/machine reset while retaining
  RAM only when policy says so and resets/preserves each modeled device class by
  explicit table.
- `cold_reset` zeroes/reinitializes RAM and machine/device state from the pinned
  deterministic reset image, then begins boot.
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

Supported exact failure stages are `machine_realized_before_release`,
`reset_vector_before_first_instruction`, `firmware_handoff_boundary`, and a
scenario-declared guest ready-point boundary. The first two are patch-native.
Firmware/ready-point failures use existing observed boundaries and stop/restart
the node without modifying guest code. Outcomes are `remain_failed`,
`retry_after`, `power_off`, or `crash`; retry count is bounded.

## Hang scopes

`cpu` hang stops vCPU execution but may allow modeled external device progress;
`node` hang stops vCPUs and device callback/service progress after safe
quiescence; selected-device hang freezes only declared registered devices.
Control, diagnostic, and recovery command processing remains available. A hang
cannot be implemented by blocking a host thread or deadlocking QEMU.

## Evidence and VMState

Evidence includes old/new lifecycle state, QMP/run state, process generation,
reset/power reason, every state-treatment policy and affected-state digest,
terminal/pre-restart fingerprints, process exit status, restart artifact/genesis
identity, and ready-point result. Patch 0059 serializes nonterminal lifecycle,
hang/recovery, boot stage, retry count, and reset policy. A crashed process is
reconstructed by the host from the recorded restart source and verified state.

## Live microtests

1. Exercise warm/cold reset, power off/on/cycle, controlled crash/restart, CPU/
   node/device hang, boot failures at every stage, and intermittent sequences.
2. Verify each RAM/register/device/interrupt/timer/queue policy with sentinel
   state through live QEMU and host network/storage adapters.
3. Trigger x86 triple fault and corresponding AArch64 fatal reset policy and
   verify the common lifecycle path.
4. Save/restore every nonterminal state; reproduce crashed restart from genesis
   and checkpoint.
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
