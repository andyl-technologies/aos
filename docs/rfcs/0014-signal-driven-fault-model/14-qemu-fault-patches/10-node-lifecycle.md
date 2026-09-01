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

Watchdogs due at the same virtual coordinate form one atomic composition set.
The adapter snapshots the full set before changing any hang or lifecycle state,
records every member's recovery at that coordinate, and applies exactly one
resolved transition. Transition severity is, from weakest to strongest,
`boot < reset < power_cycle < crash < power_off < permanent_failure`.
Downtime is the maximum requested downtime, volatile `clear` dominates
`preserve`, and device treatment is ordered
`preserve < device_reset < clear`. Equal-severity transition winners are chosen
by the lexicographically smallest binding hash; this tie-break changes only the
event identity because all mutable policies have already been composed. Every
non-winning watchdog emits `CRUCWDC1` composition evidence binding its requested
plan, resolved plan, deadline, contributor, and winner. Container iteration
order is never observable and downtime is advanced only once. Recovery,
composition, and lifecycle evidence all retain the same safe-boundary raw
icount; deferred machine-reset completion must not restamp the lifecycle event
with a later post-reset coordinate.

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
unmanifested marker is rejected before QEMU receives the lifecycle command. The
canonically ordered `world.node_fault_capabilities.ready_markers` set is bound
into launch identity, retained across the host/plugin setup boundary, and
checked independently for every selected live node. Repeated/intermittent reset behavior is a
temporal signal producing repeated lifecycle commands, not hidden retry logic.

The GPL-side Crucible plugin reports a decoded guest event marker directly to
QEMU at the event's exact raw icount. QEMU compares it with the pending marker;
the Apache host neither synthesizes readiness nor races shared-memory polling
against reset completion. A nonmatching event remains an ordinary observation.
For `require_ready`, reset completion arms the exact virtual retry deadline,
the first matching event completes the original deferred lifecycle command,
and a missed deadline performs another native machine reset. The final missed
deadline executes `exhausted`. Failure to restore preserved reset state is a
fail-closed permanent failure and never resumes the partially reset machine.
Every repeated in-process restore replaces a pending one-shot pflash post-load
state handler before registering its successor. This prevents two missed ready
deadlines from retaining duplicate callbacks and makes the final authenticated
pause safe on both x86_64 and AArch64.

`CRUCLIF1` version 4 is 304 bytes. Its first 192 bytes carry the lifecycle,
state-policy, timing, affected-byte-count, and before/after fingerprint fields.
The preserved-domain mask at offset 20 describes state QEMU actually captured
for an in-process boot, reset, or power-cycle continuation; it is zero for
terminal crash, power-off, and permanent-failure exits even when the requested
policy is `preserve`, because terminal reconstruction is owned by the host's
authenticated checkpoint and process-generation path. Affected RAM and device
byte counts measure a fixed realized-machine topology. RAM coverage is nonzero
for every supported machine; device coverage may be zero when no eligible
device region exists. Whenever a final measurement is valid, its RAM and device
counts exactly equal the corresponding pre-transition counts: a lifecycle
policy changes contents, not the realized regions covered by the snapshot. The
only final zero counts meaning "not measured" occur on the explicitly flagged
fail-closed path whose pre-exit measurement is unavailable.
The extension is exhaustive:

| Offset | Width | Field |
| ---: | ---: | --- |
| 192 | 4 | boot policy: `1 = immediate`, `2 = require_ready` |
| 196 | 4 | one-based attempt that produced this result |
| 200 | 4 | configured maximum attempt count |
| 204 | 4 | terminal exhaustion transition, or zero for `immediate` |
| 208 | 8 | exact virtual retry delay in nanoseconds |
| 216 | 8 | exact virtual ready deadline, or `UINT64_MAX` when none was armed |
| 224 | 32 | SHA-256 of the exact UTF-8 ready-marker bytes, or all zeroes |
| 256 | 32 | QEMU-measured pre-exit state SHA-256 when terminal flag bit 0 is set; all zeroes otherwise |
| 288 | 4 | effective transition after ready exhaustion or fail-closed resolution |
| 292 | 4 | terminal cause: `0 = none`, `1 = direct`, `2 = ready_exhausted`, `3 = fail_closed` |
| 296 | 4 | flags: bit 0 = pre-exit fingerprint valid; bit 1 = process exit required; no other bits are valid |
| 300 | 4 | reserved zero |

Every terminal path uses the same canonical after-state digest:
`SHA-256("CRUCTRM1" || transition_le32 || pre_exit_qemu_state_sha256)`, with
zero padding between the transition and fingerprint exactly as encoded by the
48-byte `CRUCTRM1` material. Direct terminal commands and exhausted ready-policy
retries both record the final RAM/device byte counts and the QEMU-measured
pre-exit state fingerprint before deriving that terminal digest;
neither hashes a partially filled evidence buffer as a substitute for state.
The host authenticates the event and reconstructs the digest from the published
QEMU measurement. After the enclosing boundary transaction commits, the host
issues the typed QMP terminal-completion operation, then independently reaps the
exact owned child and requires exit status `70`, `71`, or `72` for
`crash`, `power_off`, or `permanent_failure`, respectively. The QEMU event and
the independently observed process status form one supervision record; a
missing, signaled, late, or mismatched exit fails closed before relaunch.

Ready-policy exhaustion retains the originally requested transition at offset
10 and records the configured exhaustion result as the effective transition at
offset 288. A reset/restore failure uses cause `fail_closed`, effective
`permanent_failure`, and outcome `error`. It publishes a final fingerprint and
canonical terminal digest when QEMU can still measure state. If measurement is
itself unavailable, bit 0 is clear, the pre-exit field and final affected-byte
counts are zero, and the event's after-state equals its before-state. Bit 1
remains set, so this explicitly evidenced measurement failure still requires
the supervised permanent-failure exit instead of leaving a partially reset VM
runnable.

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
realization identity, and ready-marker result. Patch 0067 serializes nonterminal lifecycle,
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
