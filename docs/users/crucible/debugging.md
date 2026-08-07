# Interactive control and debugging

Crucible distinguishes canonical inspection from mutation. Reading state and
moving backward through recorded execution preserve the canonical run. Changing
execution after an attach point must create a non-canonical branch.

The current CLI exposes both concepts, but its interactive and debugger syntax
is still lower-level than the target design. Treat this page as an exact surface
reference, not as a promise of a full debugger UI.

Agents can follow the repository example skill at
[`examples/codex-skills/crucible-debugger/SKILL.md`](../../../examples/codex-skills/crucible-debugger/SKILL.md).
It treats the packaged CLI as the debugging tool, preserves causal evidence,
and requires a non-canonical fork before fault injection or guest access.

To run the complete production matrix manually and retain every command's
evidence outside the Nix checks, use:

```sh
./result/bin/crucible-debugger-live-matrix \
  --architecture all \
  --output debugger-live-evidence
```

The output directory must not exist. The matrix clears debugger backend and boot
asset overrides, generates each scenario from the BLAKE3 identities of the
packaged kernel and root image, and uses only the public daemon and CLI surfaces.
It preserves per-architecture logs, GDB transcripts, complete landed runtime
coordinates, guest-channel transcripts, package build information, and an
aggregate `result` file. `--help` reports the architectures retained by that
suite; `all` fails closed unless both x86_64 and AArch64 assets are present.

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

`query` writes an additional `interactive-query` line containing the current
lowercase lifecycle state. An accepted `stop` writes its acknowledgement,
preserves the joined actor's exact terminal snapshot across registry cleanup,
and ends interactive input immediately; lines after `stop` are not sent to the
removed session. The registry entry is already absent when the caller receives
the response. An interactive terminal therefore does not require a separate EOF
after `stop`.

The current parser accepts only the keyword; it does not parse payloads for a
duration, fault, query selector, savepoint label, or fork override. Use the
top-level `save`, `resume`, and `fork` commands for parameterized workflows. The
argumentless mutation keywords primarily exercise the session control surface.

An interactive live-QEMU `fork` is intentionally transient: its final report
retains checkpoint and oracle evidence but marks its reproduction artifact
`status=not-captured`. Run a non-interactive fork to produce a replayable child
artifact.

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

Start the remote run with `--interactive`. As soon as the daemon creates the
paused session, that client prints a diagnostic such as
`crucible: live-session ref=1:1:<seed>` on standard error. Copy the value after
`ref=` into `debug --session`; the original client may remain open while a
second process debugs it. The canonical identity uses decimal `id` and `epoch`
fields plus exactly 64 lowercase hexadecimal seed digits. It is not a network
address; the global `--daemon` option selects the daemon endpoint.

Crucible does not provide a symbol server. Supply the guest executable and
DWARF files to GDB locally. The packaged GDB includes Python scripting, TUI,
and both x86_64 and aarch64 target descriptions.

The x86_64 suite also retains matching x86_64 and AArch64 guest kernels and root
images. A scenario's `world.node.arch` selects the complete machine/CPU/console
and guest-artifact profile; do not override only `CRUCIBLE_QEMU` when changing
architectures. For custom assets, set the matching
`CRUCIBLE_KERNEL_<ARCH>`, `CRUCIBLE_ROOT_IMAGE_<ARCH>`, and
`CRUCIBLE_KERNEL_CMDLINE_<ARCH>` triplet together (`ARCH` is `X86_64` or
`AARCH64`). A partial triplet fails before QEMU starts.

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

A rejected coordinate, unavailable reverse history, or guest-introspection
policy check is returned to that debugger command without terminating the live
session. Correct the request and retry, or use the original run client to query
or stop the same session.

A session resumed from a checkpoint closure can use coordinate `goto` and
instruction reverse-step immediately. Because that closure does not contain the
pre-checkpoint event log, event, quantum, assertion, timer, and condition-based
reverse operations stop with an explicit history-floor error rather than
guessing across the missing history. Newly recorded post-resume history becomes
available at subsequent scheduler boundaries.

`--allow-mutate` only authorizes the explicit `fork-debug` verb. It does not
fork by itself, and mutation or operator-controlled execution remains rejected
until that whole-world non-canonical branch has been created.

The shipped debug fixture keeps the guest agent inactive on canonical execution.
`fork-debug` first commits the explicit non-canonical branch, hot-adds a fixed
activation-only port, and waits up to 64 scheduler quanta for the agent's typed
feature advertisement. The response lists argv exec, PTY, resize, SSH bridge,
and channel-capacity support. If activation or negotiation fails, the command
still reports the committed branch identity together with the failure reason so
the branch remains discoverable and diagnosable. All commands and stream bytes
after activation use the versioned shared-memory/doorbell protocol; the hotplug
port carries only the fixed activation token.

Custom images must include an event-driven bootstrap for the fixed activation
port and must not start or poll the agent during canonical execution. A missing
bootstrap is reported as a bounded activation failure rather than a hanging
debug command.

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

Guest channels also have a response-idle deadline. The default is 30 seconds;
set `--guest-idle-timeout <duration>` before the verb when a legitimately quiet
command needs longer. If no response arrives, Crucible closes the channel,
attempts bounded cleanup and controller-lease release, and reports an error that
distinguishes a missing fork-time agent from an indefinitely running CLI.
Durations accept `ticks`, `ns`, `us`, `ms`, or `s`.

`exec` uses direct argv execution and does not invoke a shell. `pty` bridges the
local standard streams to a guest controlling terminal. When standard input is
a terminal, the client enters raw mode, restores the original mode on every
normal exit path, and forwards `SIGWINCH` size changes to the guest PTY.

`ssh` is a transport byte bridge to the SSH server configured in the guest
agent; it is intended as an SSH `ProxyCommand`, not as an interactive SSH client
by itself. The suite exposes its AOS-built client as `./result/bin/ssh`, so this
workflow does not depend on a host OpenSSH installation. For example, wrap the
Crucible invocation in a script and configure:

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

- Local artifact, savepoint, and daemonless-session debug execution is not yet
  implemented. It exits `4` and states that no operation executed instead of
  returning a successful plan-only result.
- Executed debugger operations require an attached live production-daemon
  session. Artifact analysis remains available through `replay`, `verify`, and
  explicit savepoints.
- `fork-debug` creates a non-canonical branch. Do not use its output as a normal
  replay-oracle artifact.
- Artifact-targeted `attach-gdb` is unavailable locally; use a live daemon
  session for the persistent GDB relay.
- Packaged GDB can inspect registers and threads through a live x86_64 daemon
  relay. QEMU currently rejects GDB's optional trace-status and detach packets;
  GDB reports those packet errors even though inspection succeeds. After GDB
  disconnects, the gateway reconnects and revalidates the private QEMU RSP
  endpoint, so a new `attach-gdb` invocation can inspect the same paused runtime
  without an intervening `goto`.
- The shipped fixtures do not start the debug guest agent at fork time, so
  remote `exec`, `pty`, and `ssh` currently reach the bounded response-idle
  error instead of executing a command.
- A successful debugger runtime reposition invalidates every active guest
  channel and the next channel poll returns a typed `ClosedChannel` error.
- `goto` currently reports the target configuration identity, not the requested
  runtime coordinate. Two virtual-time or instruction-count coordinates can
  therefore print the same identity when no schedule decision separates them;
  this does not prove that reverse history exists. Reverse-step requires an
  earlier recorded schedule or event coordinate and returns exit `4` when none
  is available, including a branch opened at genesis with an empty schedule.
- Guest transcripts are operator-owned files. Runtime reposition closes the
  recorded channel; reopen a new channel and choose a new transcript path after
  repositioning.

Until these seams converge, use `verify --bisect`, `replay --check`, and explicit
savepoints as the primary failure-analysis tools.

## Agent-oriented failure exercise

The repository includes a deliberately incorrect scenario at
`.codex/skills/crucible-debugger/assets/inverted-crash-expectation.scenario.toml`
and an agent workflow in `.codex/skills/crucible-debugger/`. The scenario starts
the standard database cluster but asserts that `db-0` must remain crashed. It is an
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
scenario-authoring error from a guest crash. Local artifact `debug` commands
exit `4` with `no debug operation was executed`; use a live production-daemon
session for executed reverse operations or persistent GDB inspection. `--save-on`
controls savepoint creation, while failed runs retain a reproduction artifact
under every savepoint policy. Treat any confusing command, unexpected exit
status, or successful response that did not execute work as a debugger usability
finding.

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
its lease holder. Independent commands from the same authenticated operator use
separate holders, so finishing one command cannot close the relay or invalidate
another command already in flight. A different operator remains excluded until
the final holder closes. Internally, an acquisition token is reused for a
lost-response retry but never shared between independently released command
lifetimes. Direct release of a holder backing a live relay is rejected; relay
close owns that release. Retrying attachment for the same live session is idempotent: the
gateway reconnects the private QEMU RSP endpoint, verifies its paused state, and
replays acknowledged thread selections and hardware breakpoints before serving
the next GDB client. If a state-changing RSP reply or scheduler operation was
still pending at disconnect, or reconnection fails, the gateway deactivates the
backend and rejects later RSP requests until a runtime reposition promotes a
fresh backend.

The daemon-local address is never exposed directly to the remote operator. All
GDB bytes cross either mutual-TLS HTTP/2 or the explicitly trusted cleartext
transport, and the daemon rechecks the transport-derived principal and lease
generation on every chunk.
