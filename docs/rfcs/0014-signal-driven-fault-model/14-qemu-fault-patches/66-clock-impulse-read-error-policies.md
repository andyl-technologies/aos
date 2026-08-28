# Patch 0115: clock impulse and read-error policies

Patch `0134-crucible-clock-impulse-read-error-policies.patch` completes the
closed guest-clock policy surface for impulse transforms and x86 TSC source
failure.

## Problem

Offset, drift, and jump impulses changed the live affine transform but did not
commit their authored monotonicity or overdue-timer policy. Their typed result
therefore contradicted the requested effect unless it happened to select the
source defaults. The model also admitted `failed { read_error }`, while no
registered source advertised a deterministic architectural error path.

## Contract

Impulse application parses and joins the authored monotonicity and overdue
policies into dedicated durable impulse state before generation advancement,
timer rearm, state hashing, and evidence encoding. Retained-rule recompilation
starts from that durable state, so later rule replacement cannot silently erase
an earlier one-shot policy. The x86 TSC advertises read-error capability. A
guest `RDTSC` while that transition is active emits the normal authenticated
clock-read evidence and raises `#GP`; QEMU-internal projection uses the last
committed source value so timer and control operations remain defined without
synthesizing guest progress.

The live hardware matrix requires the non-default allow/reschedule and
fault/drop impulse combinations, the TSC read-error transition, recovery, and
the remaining closed clock and accelerator variants in isolated real-QEMU
processes.

## State identity

The shared-memory command/evidence protocol is unchanged. Clock VMState moves
from `CRUCCVS3`/section version 3 to `CRUCCVS4`/section version 4 because the
durable impulse-policy contributors are new canonical state. Old snapshots are
rejected by exact version identity rather than being decoded as the new state.
