# Patch 0055 — `crucible-vcpu-service-control`

## Purpose

Implements deterministic CPU capacity throttling, vCPU stall, and vCPU offline
state while preserving fixed topology and aggregate-icount scheduling. It is the
live backend for CPU service and vCPU state effects.

## Capability and dependencies

- Provides `qemu.cpu.service.v1` and `qemu.cpu.vcpu-state.v1` on x86-64 and
  AArch64.
- Depends on 0047–0048, fixed RR quantum/cursor, sim time control, idle deadline,
  and preemption patches.

## Service model

Each vCPU has a rational service share in `[0,1]`, a positive service-window
length in virtual nanoseconds, exact instruction credits, and remainder. The
node may additionally have a total service cap. At each window boundary:

```text
credits += floor(window_instruction_budget * share + remainder)
remainder = exact fractional remainder
```

The window instruction budget derives from the node's fixed icount/virtual-time
mapping and declared CPU capacity table, never host speed. A vCPU may execute at
most its credits and RR quantum before yielding. Credits are bounded; unused
credit policy is `discard` or bounded `carry` with explicit maximum.

Multiple throttle effects compose by minimum share/cap. A share of zero is
represented as `stalled`, not a zero rational service configuration.

## Stall and offline

- `stalled`: vCPU remains architecturally online, receives pending controller
  state according to the interrupt policy, but retires no instructions until
  recovery. Wake events do not bypass the stall.
- `offline`: vCPU is removed from the sim RR eligible set while remaining in the
  fixed guest-visible topology. Interrupt routing to it follows explicit
  reject/retain/reroute policy. This is a fault state, not QEMU CPU hotplug.
- `online`: vCPU re-enters at its canonical ascending-ID RR position after the
  transition boundary with declared credit reset/preserve policy.

If no vCPU is eligible, the node has an exact next recovery/timer/device deadline
or is hung. The scheduler may advance only through the existing authorized idle
time mechanism; it never sleeps to model throttle.

## Multi-vCPU ordering

RR selection skips ineligible vCPUs in ascending-ID rotation and records the
cursor transition. Same-boundary service/state changes apply before the next
selection. Aggregate icount remains monotone; per-vCPU retired counters advance
only on execution. Inter-vCPU IPI timing uses the existing aggregate boundary and
the interrupt policy for stalled/offline targets.

## Evidence and VMState

Evidence includes service contributors, share/cap, window, credits/remainder,
retired budget, old/new vCPU state, RR cursor, skipped selections, idle jumps,
interrupt treatment, and fingerprints. Patch 0059 serializes rule generations,
window coordinate, credits, remainder, state, recovery timers, and cursor.

## Live microtests

1. Run fixed workloads at shares 1, 1/2, 1/3, and combined caps; prove exact
   retired-instruction trajectories and virtual-time ratios on both architectures.
2. Exercise multi-vCPU unequal shares, stall, offline, re-online, credit reset/
   carry, IPI and timer delivery, and all-vCPU-ineligible deadlines.
3. Perturb host CPU load/thread scheduling and prove identical trajectories.
4. Save/restore mid-window with fractional remainder and pending interrupts.
5. Verify zero/overflow/bad rational, impossible routing, and bound errors.
6. Benchmark disabled/empty/active control; revert patch and fail live gate;
   prove non-sim RR behavior is unchanged.

## Licensing checklist

RR/TCG/CPU scheduling changes are determinism-critical GPL-side changes gated on
sim-fault mode. Public protocol carries rational service and stable vCPU IDs, not
CPU objects. Preserve notices, inventory new files, DCO-sign, and include
microtests/catalog/corresponding source.

- **[QFP-VCPU-1]** Throttle semantics MUST derive from modeled virtual time and
  instruction service, never host sleeps, cgroups, or process priority.
- **[QFP-VCPU-2]** Offline state MUST preserve fixed topology and deterministic
  interrupt/RR state across checkpoint.
