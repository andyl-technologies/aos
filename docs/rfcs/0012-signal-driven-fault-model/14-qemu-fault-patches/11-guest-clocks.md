# Patch 0057 — `crucible-guest-clock-faults`

## Purpose

Implements guest-visible clock offset, exact drift, jump, freeze, jitter/wander,
source failure/fallback, and synchronization loss without changing Crucible's
global scheduler virtual time.

## Capability and dependencies

- Provides `qemu.clock.transform.x86_64.v1`,
  `qemu.clock.transform.aarch64.v1`, and `qemu.clock.source-state.v1`.
- Depends on 0047–0048, existing deterministic RTC/icount clock patches, timer
  deadline export, and safe VMState integration.

## Clock manifest

For the realized machine QEMU reports each guest-visible clock/timer source:

- architecture counters (`TSC` and related x86 sources; AArch64 generic counter);
- RTC/time-of-day device;
- HPET/PIT/APIC timer and AArch64 generic timer where present;
- ACPI/paravirtual clocks realized by the machine;
- device clocks explicitly registered for the fault API.

Rows include source ID, base clock domain, width/wrap, read phase, programmable
timer relationship, monotonicity requirement, frequency representation,
architecture/device scope, and VMState coverage. A source not in the manifest
cannot be faulted.

## Transform model

For scheduler virtual coordinate `t`, one source value is:

```text
base = deterministic_source_value(t)
rate_value = anchor_value + round((base - anchor_base) * drift_ratio)
offset_value = rate_value + offset + accumulated_jumps
final = freeze_or_jitter(offset_value, opportunity)
```

All fields use checked integer/rational arithmetic and source width/wrap policy.
Transform changes create a new anchor `(base,value)` at the exact boundary so
rate changes are continuous unless an explicit jump occurs.

Jitter uses a bounded nonempty signed lookup table selected by the stable keyed
clock-read opportunity. Wander uses a positive update interval, bounded offset
and rate, and a bounded nonempty signed rate-increment table; all evolving state
is checkpointed. Freeze holds the declared value and requires exactly
`resume_from_frozen` or `catch_up_jump` release behavior, with no default.

## Timers

Timer compare/deadline programming stores guest source-domain values plus the
active transform generation. On transform/source changes, QEMU deterministically
recomputes the scheduler deadline or marks it unreachable while frozen. Each
transform carries exactly `fire_at_boundary`, `drop`, or `reschedule_periodic`
for timers made overdue. No timer fires in a consumer's past.

Jitter on a clock read does not implicitly jitter timer firing; timer jitter is
a separate transform on the timer source/deadline opportunity.

## Source failure and synchronization

Each guest clock has a state machine `healthy`, `degraded`, `failed`,
`fallback`, and `synchronizing`. Failure behavior is stop, invalid/error where
architecture supports it, or transition to a declared fallback source; a
`failed` command embeds exactly `stop` or `read_error`. Switching
records old/new source and continuity policy. Synchronization applies explicit
step or bounded slew with rational rate and completion threshold; no host NTP or
wall time is consulted.

## Monotonicity and wrap

Per source, policy is `allow_backward`, `clamp_monotonic`, or `fault_on_backward`.
Clamping state is checkpointed and observable. Width wrap follows architecture
modulus and is distinct from a backward fault. Time-of-day and monotonic sources
may have different policies.

## Evidence and VMState

Evidence includes source/manifest generation, base/raw/final value, anchors,
offset/rate/jump/freeze/jitter contributors, read opportunity, monotonicity/wrap
action, timer old/new deadline and action, source transition, and fingerprints.
Patch 0059 serializes transforms, anchors, wander, clamp last value, source state,
timer transform generation, and pending synchronization.

## Live microtests

1. On x86-64 and AArch64, exercise every advertised source through unmodified
   guest clock/timer reads and interrupts.
2. Cover positive/negative offset, rational fast/slow drift, jump, freeze/unfreeze
   policies, keyed jitter, wander, wrap, and backward policies.
3. Program timers across each transform/source transition and verify exact
   rearm/fire/drop behavior.
4. Fail/fallback/synchronize sources without consulting host wall time.
5. Save/restore mid-drift, frozen, jitter/wander, and synchronization states.
6. Verify global scheduler virtual time/fingerprints outside guest-clock state do
   not change from the declared clock effect.
7. Revert patch and fail live gate; prove non-sim clocks equal unpatched QEMU.

## Licensing checklist

Architecture counter, timer, RTC, paravirtual clock, and plugin changes remain
GPL-side, guarded by sim-fault transforms. Public protocol exposes typed source
IDs/values only. Preserve notices, inventory new files, DCO-sign, and include
microtests/catalog/corresponding source.

- **[QFP-CLOCK-1]** Every advertised clock source includes its timer relationship;
  read-only transformation without consistent timers is incomplete.
- **[QFP-CLOCK-2]** Guest clock effects MUST NOT alter scheduler time or consult
  host time.
