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
exec -- <program> [args...]
pty [--columns N --rows N] -- <program> [args...]
ssh
```

The Crucible suite ships its matching hermetic GNU GDB as
`./result/bin/gdb`. Start the relay in one terminal, copy the loopback address
it prints, and connect from a second terminal:

```sh
./result/bin/crucible [daemon TLS flags] \
  debug --session <id:epoch:seed> --node node-a attach-gdb

./result/bin/gdb /path/to/guest-symbols \
  -ex 'target remote 127.0.0.1:<port>'
```

The session target is the canonical identity printed by the daemon:
`id:epoch:seed`, where `id` and `epoch` are decimal integers and `seed` is
exactly 64 lowercase hexadecimal digits. It is not a network address; the
global `--daemon` option selects the daemon endpoint.

Crucible does not provide a symbol server. Supply the guest executable and
DWARF files to GDB locally. The packaged GDB includes Python scripting, TUI,
and both x86_64 and aarch64 target descriptions.

Remote time travel uses the same authenticated controller lease and stable
gateway attachment. The client sends only the requested coordinate or reverse
operation; the daemon's session actor supplies the authoritative current
configuration and event history:

```sh
./result/bin/crucible [daemon TLS flags] \
  debug --session <id:epoch:seed> --node node-a goto vtime:42000

./result/bin/crucible [daemon TLS flags] \
  debug --session <id:epoch:seed> --node node-a reverse-step event

./result/bin/crucible [daemon TLS flags] \
  debug --session <id:epoch:seed> --node node-a reverse-continue quiescent
```

`reverse-continue` accepts `quiescent`, `at:<virtual-time-ticks>`, or
`hex:<compact-predicate>`. The compact form is the canonical binary encoding of
the RFC-0010 17a predicate and supports the complete condition vocabulary.
`goto` on a remote session accepts `vtime:<ticks>` (or a bare tick count) and
`icount:<node>:<retired>` coordinates.

A session resumed from a checkpoint closure can use coordinate `goto` and
instruction reverse-step immediately. Because that closure does not contain the
pre-checkpoint event log, event, quantum, assertion, timer, and condition-based
reverse operations stop with an explicit history-floor error rather than
guessing across the missing history. Newly recorded post-resume history becomes
available at subsequent scheduler boundaries.

`--allow-mutate` only authorizes the explicit `fork-debug` verb. It does not
fork by itself, and mutation or operator-controlled execution remains rejected
until that whole-world non-canonical branch has been created.

The remote guest-introspection commands and transport are present, but the
shipped production VM lifecycle does not yet activate `crucible-guest agent`
when `fork-debug` creates the non-canonical branch. Consequently `exec`, `pty`,
and `ssh` are not yet operational against the shipped fixtures. Images used for
development must arrange an agent themselves; production users should treat
these verbs as preview-only until the fork-time activation and live gates in
RFC-0010 T-DBG-12 and T-DBG-14 are complete.

The intended workflow first creates the explicit branch, then opens a channel
in a second invocation. Both commands acquire and release the exclusive
controller lease:

```sh
./result/bin/crucible [daemon TLS flags] \
  debug --session <id:epoch:seed> --node node-a --allow-mutate fork-debug

./result/bin/crucible [daemon TLS flags] \
  debug --session <id:epoch:seed> --node node-a --allow-mutate \
  exec -- /bin/uname -a

./result/bin/crucible [daemon TLS flags] \
  debug --session <id:epoch:seed> --node node-a --allow-mutate \
  pty --columns 120 --rows 40 -- /bin/bash
```

Add `--record-transcript <path>` before `exec`, `pty`, or `ssh` to retain the
exact bounded guest-agent exchange. The CLI creates the path exclusively and
refuses to overwrite an existing file. A transcript starts with the eight-byte
`CRGT` version-1 header. Each following frame contains a one-byte direction
(`1` host-to-guest or `2` guest-to-host), three zero bytes, a little-endian
32-bit record length, and one complete `CRGI` record. Recording stops with an
error at 64 MiB. The file is branch-local diagnostic evidence: it is available
only for an explicitly authorized non-canonical guest channel and is never
included in canonical replay artifacts.

`exec` uses direct argv execution and does not invoke a shell. `pty` bridges the
local standard streams to a guest controlling terminal. When standard input is
a terminal, the client enters raw mode, restores the original mode on every
normal exit path, and forwards `SIGWINCH` size changes to the guest PTY.

`ssh` is a transport byte bridge to the SSH server configured in the guest
agent; it is intended as an SSH `ProxyCommand`, not as an interactive SSH client
by itself. For example, wrap the Crucible invocation in a script and configure:

```text
Host crucible-guest
  ProxyCommand /path/to/crucible-guest-proxy
```

The bridge does not grant access to the daemon host. The daemon role must grant
`observe,control,mutate,shell` for the
fork workflow. Guest channels are bounded and fail closed on malformed records,
backpressure, stale controller leases, or canonical sessions.

After that fork, GDB `continue`, `step`, and `vCont` requests are mediated by the
gateway and admitted as ordinary scheduler-owned session commands. They are
never forwarded directly to QEMU. GDB `step` currently means one deterministic
scheduler quantum; raw QEMU single-instruction stepping remains disabled.

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
- Local artifact debugging currently emits planned operations and live probe
  evidence; the persistent GDB listener is available for an attached daemon
  session.
- `fork-debug` creates a non-canonical branch. Do not use its output as a normal
  replay-oracle artifact.
- Artifact-targeted `attach-gdb` does not keep a GDB session open after the
  bounded local probe exits.
- Packaged GDB can inspect registers and threads through a live x86_64 daemon
  relay. QEMU currently rejects GDB's optional trace-status and detach packets;
  GDB reports those packet errors even though inspection succeeds.
- The shipped fixtures do not start the debug guest agent at fork time, so
  remote `exec`, `pty`, and `ssh` are not yet production-ready.
- A successful debugger runtime reposition invalidates every active guest
  channel and the next channel poll returns a typed `ClosedChannel` error.
- Guest transcripts are operator-owned files. Runtime reposition closes the
  recorded channel; reopen a new channel and choose a new transcript path after
  repositioning.

Until these seams converge, use `verify --bisect`, `replay --check`, and explicit
savepoints as the primary failure-analysis tools.

## Agent-oriented failure exercise

The repository includes a deliberately incorrect scenario at
`.codex/skills/crucible-debugger/assets/inverted-crash-expectation.scenario.toml`
and an agent workflow in `.codex/skills/crucible-debugger/`. The scenario runs a
healthy HTTP workload but asserts that its node must remain crashed. It is an
operator exercise, not a Nix check: the expected result is a retained failure
artifact and the expected diagnosis is an inverted scenario assertion.

Run it with a fixed seed, finite budget, and failure retention:

```sh
mkdir -p /tmp/crucible-debugger-artifacts
./result/bin/crucible \
  --seed 0xdeb6 \
  --format table \
  --artifact-dir /tmp/crucible-debugger-artifacts \
  run .codex/skills/crucible-debugger/assets/inverted-crash-expectation.scenario.toml \
  --until property \
  --save-on fail \
  --max-quanta 100
```

An agent or operator should report the terminal outcome, violated assertion,
seed, frontier, quanta, artifact path, and the evidence that distinguishes a
scenario-authoring error from a guest crash. Artifact `debug` commands currently
emit `debug-plan execution=planned-only`; use a live production-daemon session
for executed reverse operations or persistent GDB inspection. `--save-on`
controls savepoint creation, while failed runs retain a reproduction artifact
under every savepoint policy. Treat any confusing command, unexpected exit
status, or plan-only response that looks like executed work as a debugger
usability finding.

## Remote GDB attachment

Start `serve --production-qemu` with mutual TLS and grant the operator
certificate at least `observe,control`; see [Daemon operation](daemon.md). After
creating a paused inline-scenario session, use its full reference in
`id:epoch:64-lowercase-hex-seed` form:

```sh
./result/bin/crucible \
  --daemon https://daemon.example:9000 \
  --daemon-ca server-ca.crt \
  --daemon-cert operator.crt \
  --daemon-key operator.key \
  debug \
  --session 7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --node node-a \
  --gdb-listen 127.0.0.1:0 \
  attach-gdb
```

The CLI acquires the session's exclusive controller lease, asks the daemon to
attach its private standalone gateway, binds the requested client-side loopback
listener, and prints the actual address. Connect ordinary GDB to that address in
a second terminal. Closing GDB or pressing Ctrl-C closes the relay and releases
the lease. Retrying attachment for the same live session is idempotent.

The daemon-local address is never exposed directly to the remote operator. All
GDB bytes cross either mutual-TLS HTTP/2 or the explicitly trusted cleartext
transport, and the daemon rechecks the transport-derived principal and lease
generation on every chunk.
