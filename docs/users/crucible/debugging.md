# Interactive control and debugging

Crucible distinguishes canonical inspection from mutation. Reading state and
moving backward through recorded execution preserve the canonical run. Changing
execution after an attach point must create a non-canonical branch.

The current CLI exposes both concepts, but its interactive and debugger syntax
is still lower-level than the target design. Treat this page as an exact surface
reference, not as a promise of a full debugger UI.

## Interactive run control

Start paused at genesis and read commands from standard input:

```sh
./result/bin/crucible \
  run scenario.toml \
  --interactive
```

The line parser ignores blank lines and text after `#`. It accepts these command
keywords:

```text
continue
pause
step                  alias: step-quantum
step-event
step-assertion
step-timer
step-duration
inject
inject-fault
heal                  alias: heal-fault
save                  alias: create-savepoint
fork
query
stop
```

Commands are acknowledged at deterministic session boundaries, not at the host
wall-clock instant the line was read.

The current parser accepts only the keyword; it does not parse payloads for a
duration, fault, query selector, savepoint label, or fork override. Use the
top-level `save`, `resume`, and `fork` commands for parameterized workflows. The
argumentless mutation keywords primarily exercise the session control surface.

For a bounded inspection session, pipe commands explicitly:

```sh
printf 'query\nstep\nquery\nstop\n' | \
  ./result/bin/crucible run scenario.toml --interactive
```

Avoid an unbounded `continue` in a scripted interactive session unless the
scenario has an independent terminal condition.

## Live status

`run`, `resume`, and `fork` accept `--watch`. It adds session status updates to
the backend's collected run evidence. Table output prints collected updates as
human-readable `run-watch` lines. JSON and JSONL remain canonical event-log
renderings and do not add a separate non-canonical status stream.

## Debug command

`debug` accepts either an artifact/savepoint target or a running session:

```sh
./result/bin/crucible \
  debug failure.crucible \
  --at-failure
```

Coordinate selectors are mutually exclusive:

```text
--at <virtual-time-or-node-icount-coordinate>
--at-event <sequence>
--at-failure
--at-checkpoint <blake3:hash>
```

The command also exposes:

```text
--node <id>
--gdb-listen <addr>
--read-only
--allow-mutate
--checkpoint-stride <n>
```

Debugger verbs are subcommands:

```text
attach-gdb
fork-debug
goto <coordinate>
reverse-step <instruction|quantum|event|assertion|timer>
reverse-continue <condition>
```

`--allow-mutate` only authorizes the explicit `fork-debug` verb. It does not
fork by itself, and mutation or operator-controlled execution remains rejected
until that whole-world non-canonical branch has been created.

For example:

```sh
./result/bin/crucible \
  debug failure.crucible \
  --at-failure \
  reverse-step event
```

## Current limitations

- The production debug path requires the packaged QEMU backend even for
  admission and identity checks.
- The CLI currently emits planned debug operations and live probe evidence; it
  is not yet a persistent interactive debugger shell.
- `fork-debug` creates a non-canonical branch. Do not use its output as a normal
  replay-oracle artifact.
- `attach-gdb` currently records the planned mediated-gdbstub operation; it does
  not keep a GDB proxy or debugger session open after the bounded probe exits.
- `--session` is a debugger target shape, but the packaged `serve` backend is
  not currently the production QEMU lifecycle. Do not treat daemon debug as
  equivalent to local live-VM debug.

Until these seams converge, use `verify --bisect`, `replay --check`, and explicit
savepoints as the primary failure-analysis tools.
