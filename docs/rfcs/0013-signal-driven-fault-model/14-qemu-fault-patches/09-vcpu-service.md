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

One rule carries a nonempty sorted vCPU set, reduced rational capacity in
`(0,1]`, positive instruction quantum, and `work_conserving` or `strict_cap`
discipline. Each selected vCPU has exact instruction credits and remainder. At
each scheduler service quantum:

```text
credits += floor(quantum_instructions * capacity + remainder)
remainder = exact fractional remainder
```

The virtual duration derives from the node's fixed icount/virtual-time mapping,
never host speed. A vCPU may execute at most its credits and RR quantum before
yielding. Credits are bounded. `strict_cap` keeps each selected vCPU's ledger
independent; `work_conserving` permits another eligible selected vCPU to consume
unused service in canonical RR order. No unbounded carry or hidden service
policy exists.

Multiple throttle effects compose by minimum share/cap. A share of zero is
represented as `stalled`, not a zero rational service configuration.

A state-only rule change preserves every service-ledger field. A service-rule
change at a node boundary explicitly interrupts each affected partial window:
the backend emits the old window's retired, remaining-credit, remainder, and
donation evidence with `configuration_interrupted = true`, advances no virtual
time for the discarded old allowance, and starts the new controller with an
empty window at the next selection. No credit or fractional remainder crosses a
service-controller change. Removing the final service rule uses the same
closure, so configuration changes cannot silently discard reserved evidence.

## Stall and offline

- `stalled`: vCPU remains architecturally online and controller pending state is
  retained, but it retires no instructions until
  recovery. Wake events do not bypass the stall.
- `offline`: vCPU is removed from the sim RR eligible set while remaining in the
  fixed guest-visible topology. Interrupts retain architecture controller state
  until the vCPU is online or a separate interrupt fault changes disposition.
  This is a fault state, not QEMU CPU hotplug.
- `online`: vCPU re-enters at its canonical ascending-ID RR position after the
  transition boundary and resumes its checkpointed service ledger. Online must
  not carry a recovery event; offline/stalled must carry one.

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
interrupt treatment, and fingerprints. Patch 0067 serializes rule generations,
window coordinate, credits, remainder, state, recovery timers, and cursor.

## Live microtests

1. Run fixed workloads at shares 1, 1/2, 1/3, and combined caps; prove exact
   retired-instruction trajectories and virtual-time ratios on both architectures.
2. Exercise multi-vCPU unequal shares, both service disciplines, stall, offline,
   re-online, IPI/timer pending state, and all-vCPU-ineligible deadlines.
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
