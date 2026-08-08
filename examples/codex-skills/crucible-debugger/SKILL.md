---
name: crucible-debugger
description: Operate the Crucible CLI as a debugging tool for deterministic VM scenarios. Use when an agent must reproduce a failing scenario, inspect logs and assertions, attach GDB, traverse recorded history, create an explicit noncanonical fork, inject faults, or run guest exec, PTY, and SSH introspection without changing canonical evidence.
---

# Crucible Debugger

Treat Crucible as the source of truth. Preserve the scenario, seed, trace,
failure artifact, session identity, and every debugger response needed to explain
the failure.

## Prepare

1. Read `docs/users/crucible/debugging.md` and the scenario under investigation.
2. Use the packaged `crucible` and matching QEMU/plugin outputs. Do not substitute
   a model double for a claimed live result.
3. Create a new artifact directory and use `--format json` for machine-readable
   output. Never overwrite an existing transcript or failure artifact.
4. Record the exact command, seed, backend selection, and exit status for each run.

For the complete packaged production matrix, run
`crucible-debugger-live-matrix --architecture all`. It retains a new evidence
directory and refuses to overwrite an existing one. The command clears external
backend/asset overrides and binds generated scenarios to the packaged kernel and
root-image digests. Use `--output NEW-DIR` when the evidence location must be
stable; check `--help` before requesting `all` on a suite that may retain only
its native guest architecture.

## Reproduce before changing anything

Run the scenario at least twice with the same seed and compare the terminal
outcome, causal log, and fingerprint. Start an interactive daemon session when
live inspection is required:

```text
crucible --daemon <endpoint> --trusted-unauthenticated-daemon \
  run <scenario.toml> --interactive --backend qemu --seed <seed> \
  --watch --format json
```

Use authenticated daemon options instead of the trusted cleartext option when
certificates are available. Keep the run process alive and capture the printed
`id:epoch:seed` session identity.

## Inspect the canonical run read-only

Start with `--read-only`. Inspect the event log, assertion state, landed runtime
coordinate, scheduler frontier, event offset, node instruction counts, and
fingerprints. Use `attach-gdb` only for reads and hardware breakpoints.

Exercise history deliberately:

```text
crucible --daemon <endpoint> --trusted-unauthenticated-daemon \
  debug --session <session> --node <node> --read-only reverse-step event

crucible --daemon <endpoint> --trusted-unauthenticated-daemon \
  debug --session <session> --node <node> --read-only reverse-continue quiescent

crucible --daemon <endpoint> --trusted-unauthenticated-daemon \
  debug --session <session> --node <node> --read-only goto vtime:<ticks>
```

Verify that each successful operation reports the requested and landed runtime
coordinates. For reverse operations, require a strictly earlier event/runtime
tuple even when the configuration hash repeats. Treat an explicit history-floor
error as evidence that the requested history was not retained, not as a match.

## Fork before mutation or guest access

Never inject a fault, advance under operator control, or open a guest channel on
the canonical run. Create one explicit whole-world branch first:

```text
crucible --daemon <endpoint> --trusted-unauthenticated-daemon \
  debug --session <session> --node <node> --allow-mutate fork-debug
```

Require the response to identify the noncanonical fork marker and negotiated
guest-agent features. If activation fails, preserve the returned branch identity
and failure reason; do not assume the branch disappeared.

Use `exec` for bounded probes such as `uname`, `cat`, `ps`, or application health
commands. Use `pty` only when terminal behavior matters. Use `ssh` as a byte
bridge to the configured in-guest SSH server, never as access to the Crucible
host. Record a transcript when the bytes are needed as diagnostic evidence.
While a channel is open, let that CLI invocation retain the internal scheduler
run; do not issue independent GDB run control concurrently. A reposition
releases that run before replacement and returns a typed channel-closure error
when the new runtime commits.

## Diagnose systematically

1. Locate the first assertion failure or divergence in the causal log.
2. Rewind to the preceding event or quantum and inspect the landed coordinate.
3. Compare relevant registers, memory, device state, logs, and guest process state.
4. Fork and replay the smallest hypothesis-changing action, including a typed
   injected fault when appropriate.
5. Repeat from the same recorded coordinate and seed. Reject explanations that
   do not reproduce.
6. Report the earliest causal discrepancy, the supporting commands and evidence,
   and any debugger behavior that prevented a conclusion.

## Finish

Close guest channels, release the controller lease, and stop the interactive
session. Distinguish product bugs from scenario failures. Report unsupported,
timed-out, malformed, or architecture-specific behavior exactly; do not silently
fall back to a different backend or command path.
