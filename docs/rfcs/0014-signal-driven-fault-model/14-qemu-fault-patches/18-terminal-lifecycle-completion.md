# Patch 0064 — `crucible-terminal-lifecycle-completion`

## Purpose

Separates a terminal lifecycle mutation from process termination so the Apache
host can validate the complete fault boundary before allowing an irreversible
QEMU exit.

## Capability and dependencies

- Extends `qemu.node.lifecycle.v1` evidence to `CRUCLIF1` version 4.
- Depends on patch 0056 lifecycle execution and patch 0063's exact paused-state
  handoff.
- Changes only QEMU/plugin GPL-side run-state and QMP behavior. The public
  evidence bytes and versioned QAPI command remain the process boundary.

## Two-phase terminal protocol

1. Patch 0056 applies the requested state policies at the safe boundary and
   publishes one `CRUCLIF1` version 4 event. Requested and effective transitions,
   terminal cause, fingerprint validity, and exit requirement are explicit.
2. QEMU records exactly one pending terminal decision but remains paused and
   control-responsive. It does not request process shutdown while the host is
   still validating the event batch or coupled host adapters.
3. The host validates the entire batch, commits the enclosing fault boundary,
   and retains the typed terminal decision.
4. The host sends the dedicated terminal-completion command specified by patch
   0065, binding the action, evidence, and process generation. The command never
   resumes guest execution.
5. The host independently reaps the exact owned child and compares its process
   status with `crash = 70`, `power_off = 71`, or `permanent_failure = 72`.

QMP `cont` always retains its ordinary behavior and is never an authorization
surface. Builds without plugin support reject the dedicated completion command.

## Failure and concurrency rules

- A second lifecycle transition is rejected while a terminal decision is
  pending.
- Ready exhaustion records the authored reset/boot/power-cycle transition and
  the distinct effective terminal transition.
- Reset/restore failure emits one typed error event and one deferred command
  failure, records effective `permanent_failure`, and remains paused until QMP
  authorization.
- Failure to fingerprint the fail-closed state is represented explicitly; it
  never suppresses the required permanent-failure exit.
- A repeated QMP completion cannot request a second exit.
- A missing acknowledgement, timeout, signal death, or wrong exit status
  quarantines the process generation. It is never reclassified as an ordinary
  crash.

## Live gates

1. Reject a corrupt version, cause, flag, effective transition, reserved field,
   terminal digest, or process status.
2. Hold QMP responsive after the event and prove that the child remains alive
   until the host completes the boundary.
3. Exercise direct terminal, ready exhaustion, fail-closed with fingerprint,
   and fail-closed without fingerprint.
4. Prove normal QMP `cont` behavior with and without a pending terminal decision
   in plugin and non-plugin builds.
5. Save the post-mutation restart state before authorization, reap the exact
   child, and verify the lifecycle supervisor's generation replacement or
   explicit offline state.

## Licensing checklist

The implementation is GPL-side, DCO-signed, listed in the QEMU source and
license inventories, included in corresponding source, and exercised by the
aggregate ABI, inertness, and license-boundary gates.
