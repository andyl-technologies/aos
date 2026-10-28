# Time-travel debugging

Crucible lets an operator attach an ordinary GDB client to a VM node at an
exact virtual-time coordinate, inspect it, and move it backward and forward
through deterministic history. This page describes how that works inside the
engine, the session actor, the daemon lifecycle, and the standalone debugger
gateway process. For command usage, see the operator guide in
[../../users/crucible/debugging.md](../../users/crucible/debugging.md).

Debugging is a projection of machinery Crucible already has. Attach is an
`instantiate`. Time travel restores a checkpoint and replays forward. A
mutating branch is a fork. The event log supplies coordinates. There is no
reverse engine, no per-instruction undo log, and no clock other than virtual
time. The only new rule fences off mutation: guest-visible state cannot change
until the operator explicitly creates a non-canonical debug branch.

## Source map

| Concern | Location |
| --- | --- |
| Debug requests, reports, and contracts | `crates/crucible/crucible-engine/src/model/debug.rs` |
| Attach, goto, reverse, and branch operations | `crates/crucible/crucible-engine/src/model/temporal_graph/core/debug_navigation.rs` |
| Reverse-grain resolution and bisection | `crates/crucible/crucible-engine/src/model/temporal_graph/debug_helpers.rs`, `debug_storage.rs` |
| Non-canonical fork marker | `crates/crucible/crucible-engine/src/scheduler/event_log.rs` (`SchedulerEventLogEntry::fork_marker`) |
| Session commands and branch gating | `crates/crucible/crucible-session/src/session/commands.rs`, `engine.rs`, `actor.rs` |
| Debugger lifecycle, roles, and leases | `crates/crucible/crucible-session/src/session/debug_coordinator.rs` |
| Live runtime replacement | `crates/crucible/crucible-daemon/src/vm_lifecycle/runtime.rs`, `runtime/debug_evidence.rs` |
| Gateway client (Apache side) | `crates/crucible/crucible-control-server/src/debug_gateway.rs` |
| Remote debug routes | `crates/crucible/crucible-control-server/src/server/debug_reposition.rs` |
| Gateway wire protocol | `crates/crucible/crucible-qemu-protocol/src/debug_gateway.rs` |
| Gateway process (GPL side) | `crates/crucible/crucible-qemu-debug-gateway/` (binary `crucible-debug-gateway`) |
| QEMU `-gdb` launch option | `crates/crucible/crucible-qemu-host/src/launch/control_channels.rs` (`QemuGdbstubChannelConfig`) |
| CLI planning and relay | `crates/crucible/crucible-cli/src/cli/triage_debug/` |
| Hermetic GDB | `pkgs/tools/gdb.nix` |

## Process layout

```text
operator GDB
   |  RSP over TCP (client loopback, default 127.0.0.1:0)
crucible debug ... attach-gdb          CLI relay; holds no debug state
   |  HTTP/2 with mutual TLS, or an explicitly trusted cleartext bind
crucible serve --production-qemu       daemon; session actor owns all state
   |  CRDBGW1 frames over a private Unix control socket
crucible-debug-gateway                 GPL-2.0-only process; owns the GDB stream
   |  RSP over a private Unix socket
QEMU -gdb <private endpoint>           one per node, replaced on time travel
```

The gateway is a separate GPL-2.0-only process. The Apache-licensed daemon
never links it and never handles QEMU objects. The two processes exchange
only owned byte frames from `crucible-qemu-protocol`, which is permissive and
has no QEMU dependency. This keeps the license boundary described in
[../../legal/licensing.md](../../legal/licensing.md) intact.

## Attach

### An attach is an instantiate

A debug attach is an `instantiate` of the checkpoint configuration that the
operator's coordinate resolves to. `TemporalGraph::debug_attach` calls
`TemporalGraph::resume` and adds metadata for the gdbstub channel. It records
no scheduler decision and has no debug-specific realization path. The
attached runtime is an ordinary instantiated runtime, produced by the same
priority-ordered branches as any other realization (exact restore, ancestor
replay, or baked genesis plus replay; see
[execution-model.md](execution-model.md)).

`DebugAttachReport::uses_instantiated_runtime` checks that the configuration,
checkpoint, and reduced state of the report match the realized runtime.

### The fourth channel role

A QEMU node normally has three channel roles (see
[qemu-integration.md](qemu-integration.md)). A debug attach adds a fourth.
`DebugAttachChannelSet::four_channel_debug_session` names all four:

| `DebugAttachChannelKind` | Carries |
| --- | --- |
| `PluginIpcControl` | Setup and teardown only |
| `SharedMemoryHotPath` | The per-quantum data plane |
| `QmpMachineControl` | Out-of-band machine control |
| `Gdbstub` | Out-of-band debugger packets |

The gdbstub carries no per-quantum timing and no frame data, and it is not
part of the scheduler's total order. `DebugGdbstubChannel` records this as
`mediated_by_crucible`, `out_of_band`, `!carries_per_quantum_timing`, and
`!carries_frame_data`. QEMU exposes its gdbstub only through `-gdb` on a
relative Unix socket inside its guarded run directory, and only for debug
launches. The gateway is its sole client.

## Read-only inspection

Read-only inspection is the default and preserves determinism exactly.
Register reads, memory reads, backtraces, thread or vCPU enumeration, and
watchpoint value reads (`DebugReadOnlyInspectionKind`) append no causal
event-log entry, change no `Configuration`, and advance no virtual time.

`TemporalGraph::read_only_debug_inspection` takes `&self`, so the type system
prevents it from recording graph state. Attach, inspection, and detach are
recorded only as observational entries. They are `diagnostic` events named
`debug.attach`, `debug.inspect.<kind>`, and `debug.detach`, and the
determinism comparison excludes them by construction (see
[event-log.md](event-log.md)).

`DebugReadOnlyInspectionReport::proves_read_only` checks that:

- the graph, configuration, checkpoint, and runtime footprints are unchanged;
- the requested virtual time equals the checkpoint's time;
- the canonical causal subsequence is byte-identical with and without the
  debugger observations; and
- every debugger observation is non-causal.

## Canonical breakpoints

Canonical breakpoints are hardware/out-of-band. A breakpoint on the canonical
run must not patch a trap instruction into guest memory, because that byte is
part of guest state and would change the causal history.
`TemporalGraph::canonical_debug_breakpoint` resolves each request to a
`DebugBreakpointMechanism`:

| Target | Mechanism |
| --- | --- |
| `EngineCondition` | `EngineCondition`, a condition evaluated by Crucible at deterministic boundaries (see [conditions-and-triggers.md](conditions-and-triggers.md)) |
| `GuestAddress` | `QemuHardwareBreakpoint`, a QEMU hardware breakpoint or debug-register trap |
| `GuestMemoryPatchOnly` | None: fails with `EngineError::DebugBreakpointRequiresAllowMutate` |

A client software-breakpoint request is satisfied transparently through the
hardware mechanism. `DebugBreakpointReport::transparently_satisfies_software_request`
holds when `mutates_guest_memory` and `memory_patch_used` are both false. The
refusal error tells the operator to rerun with `--allow-mutate` and fork a
non-canonical branch. It is never silently downgraded to a memory patch.

The gateway enforces the same rule on the wire. Before a breakpoint packet
reaches QEMU, `canonical_breakpoint_packet` rewrites a software breakpoint
`Z0,` or `z0,` to the hardware form `Z1,` or `z1,`. If QEMU refuses the
hardware breakpoint, the refusal goes back to GDB; no memory trap is tried.

## Time travel

### `goto` is restore-nearest-checkpoint then replay

"Go to coordinate T" in either direction is the ancestor-replay branch of
`instantiate`, aimed at T instead of the tip. `TemporalGraph::debug_goto`:

1. Resolves the `DebugCoordinate` to a target `Configuration` and checks that
   it belongs to the same scenario.
2. Selects the restore configuration through `debug_restore_configuration`:
   the exact target snapshot if one exists, else the nearest cached ancestor,
   else baked genesis.
3. Realizes the target with `resume`, replaying the schedule suffix after the
   restore point.
4. Materializes a target checkpoint and checks it with the replay oracle.

A coordinate reached by `goto` is therefore the same content-addressed
configuration that running forward would reach. A corrupt cached snapshot
cannot become a debugger-only shortcut. On a replay-oracle mismatch,
`debug_goto` returns `EngineError::DebugGotoReplayOracleMismatch`. It carries
a `DebugReplayOracleBisectionRequest` that binary-searches cached prefixes and
names `first_different_schedule_prefix_len`, localizing any divergence by
bisection.

`DebugGotoReport` keeps the requested coordinate separate from the landed
coordinate: target configuration, landed virtual time, schedule-prefix length,
restore configuration and checkpoint, replay-suffix length, and the oracle
result. Two coordinates can share a configuration identity when no schedule
decision separates them, so live callers compare the full landed tuple, not
only the configuration hash.

### Coordinates

`DebugCoordinate` has five forms:

| Variant | Meaning |
| --- | --- |
| `Configuration` | An already-resolved configuration |
| `Checkpoint(hash)` | A checkpoint or configuration content address |
| `EventSequence(seq)` | An event-log entry, through a caller-supplied sequence-to-configuration map |
| `VirtualTime(t)` | The latest checkpoint at or before `t` |
| `NodeIcount { node, icount }` | The latest checkpoint where `node` is at or before `icount` |

`TemporalGraph::debug_resolve_target` maps the operator selectors to a goto
request:

| `DebugTargetSelector` | CLI flag | Resolves to |
| --- | --- | --- |
| `At(coordinate)` | `--at` | The coordinate |
| `AtEvent(seq)` | `--at-event` | The event's configuration |
| `AtFailure` | `--at-failure` | The first assertion-violation event |
| `AtCheckpoint(hash)` | `--at-checkpoint` | The checkpoint |
| `Divergence(DebugDivergenceCoordinate)` | none | A bisection `(node, icount, kind)`, used directly |

`DebugDivergenceCoordinate::from_event_log_causal_divergence` converts a
node-local event-log divergence point, so divergence-bisection output can be
used as a goto target without translation.

### Reverse step

A reverse step finds an earlier coordinate of a given grain and delegates the
move to `debug_goto`. `DebugReverseStepGrain` mirrors the forward step modes:

| Grain | Earlier coordinate |
| --- | --- |
| `Instruction` | The configuration with the last schedule decision removed |
| `Quantum` | The latest earlier `EvaluationBoundary(Quantum)` entry |
| `Event` | The latest earlier `ResolvedHappening`, `Observable`, `TriggerFired`, or `TriggerActionApplied` entry |
| `Assertion` | The latest earlier `AssertionEvaluated` or `GuestAssertionMarker` observable, or trigger entry |
| `Timer` | The latest earlier I/O completion, or `ArmTimer` or `CancelTimer` action |

The event-log grains search entries with a sequence below the current event
limit. If none exists, the step fails with
`EngineError::DebugTimeTravelNoEarlierCoordinate` instead of running past the
start of history. A session resumed from a checkpoint closure lacks the
pre-checkpoint log, so only coordinate `goto` and instruction-grain reverse
work there until new history is recorded.

### Reverse continue

`debug_reverse_continue` follows the latest-log-coordinate rule. It scans
checked event-log prefixes backward, evaluates the shared condition
vocabulary with `ConditionEvaluationPass` over each prefix, and picks the
latest matching coordinate at or before the current log limit. Then it calls
`debug_goto`. Evaluation is a pure function of the log prefix and never
re-executes the guest. `debug_reverse_continue_with_leaf_oracle` accepts a
host-side resolver for named and guest-marker leaves, which otherwise
evaluate to false.

### Per-node and whole-world scope

- `debug_per_node_time_travel` moves one node to an exact node-icount on the
  attached configuration's linear schedule family. It derives only that
  node's material, from the baked restore and the replay suffix. Every other
  node keeps its attached runtime material and is not re-instantiated.
- `debug_whole_world_time_travel` moves the whole world to a prefix of the
  current configuration. `DebugWholeWorldTarget` is a prefix length, a
  virtual time, or an event sequence. The prefix is realized through
  `debug_goto` and nothing is appended. Whole-world time travel is a fork
  that has not yet diverged.

Live production repositioning is always whole-world (see
[Live runtime replacement](#live-runtime-replacement)).

### Checkpoint cadence

Reverse latency depends on the replay distance from the nearest
materialized checkpoint. `debug_apply_checkpoint_cadence` walks the prefixes
of the current schedule. It selects each prefix whose length is a multiple of
a non-zero `DebugCheckpointStride`, then asks the ordinary advisory cache
(`MaterializationPolicy`) to materialize it. This is purely a cache decision:
the denoted configurations do not change, and eviction is always safe. With
`DebugCheckpointCadenceRequest::thin_only`, every selected point stays thin,
and time travel stays pure thin/replay. A fat checkpoint is admitted only when
its snapshot is complete. The `--checkpoint-stride` CLI flag validates a
non-zero stride and records the cadence in the debug plan.

## The non-canonical debug branch

### Gating

After a debugger reposition, the session sets `debug_branch_required`. While
it is set, any command for which
`SessionCommand::requires_non_canonical_debug_branch` is true fails with
`SessionError::DebugNonCanonicalBranchRequired` and changes nothing. Those
commands are `Continue`, `Step`, `SetBreakpoint`, `RemoveBreakpoint`, and
`GuestIntrospection`. Rejecting a request never creates a branch as a side
effect. `AttachGdb`, `DebugGoto`, `DebugReverseStep`, and
`DebugReverseContinue` are read-only commands and stay available.

The only way out is an explicit `SessionCommand::DebugForkNonCanonical`. On
the CLI this is the `fork-debug` verb, which requires `--allow-mutate`.
`--allow-mutate` only authorizes that verb. It never forks or mutates by
itself.

### What the fork records

`TemporalGraph::debug_non_canonical_branch` takes a
`DebugNonCanonicalBranchRequest` with a trigger and an ordered list of
actions. The first action must match the trigger, or the call fails with
`EngineError::DebugNonCanonicalBranchMissingTriggerEvidence`. The triggers
are `GuestRegisterWrite`, `GuestMemoryWrite`, `MemoryPatchBreakpoint`,
`OperatorContinue`, `OperatorStep`, `ScheduleExpressibleEdit`, and
`GuestIntrospection`.

The branch is stored as debug metadata, not as a canonical `Configuration`.
Operator actions are split by whether the model can express them:

| Action | Recorded as |
| --- | --- |
| Inject or heal a fault, override a decision, a control operation | `schedule_expressible_decisions` and control-log operations |
| Raw register write, memory write, memory-patch breakpoint | A `DebugEditScript` hung off the fork point |

A `DebugEditScript` is an ordered list of `DebugGuestEdit` entries (node,
kind, coordinate, target, exact bytes). With `model_reproducible: false`, it
lets the operator re-derive the branch, but it is never a
`(seed, scenario, schedule)` artifact.

The branch is marked as non-canonical everywhere it can be seen:

- **Event log.** `SchedulerEventLogEntry::fork_marker` appends a causal
  `fork` entry with the diagnostic name `debug.non_canonical_fork`. Its
  attributes are `non_canonical=true`, `canonical=false`, `branch`,
  `fork_point`, `from_checkpoint_id`, and `schedule_delta`.
- **Live status.** `DebugNonCanonicalLiveStatus` carries the label
  `non-canonical-debug-branch`.
- **Graph view.** `TemporalGraph::debug_non_canonical_branch_view` returns
  the branch.

`DebugNonCanonicalBranchReport::proves_non_canonical_debug_branch` combines
these checks:

- `canonical_run_bit_identical`: the canonical graph, runtime footprint, and
  causal event-log projection are unchanged;
- `excluded_from_oracles_and_artifacts`: the branch has no thin derivation,
  so the replay oracle never sees it;
- `visibly_marked_non_canonical`; and
- `inside_virtual_time_single_execution_path`.

The branch still runs under TCG with instruction counting, and the scheduler
still owns the total order. That makes it a third category of execution,
alongside the canonical run. It is not a detach to a free-running QEMU,
which Crucible does not support. A branch forfeits reproducibility, not
determinism.

## The debugger gateway

### Process and sockets

```text
crucible-debug-gateway --control-socket <absolute-path>
                       [--owner-gdb-socket <absolute-path>]
```

The daemon spawns the gateway through
`DebugGatewayProcess::launch_with_owner_unix`, without a shell, under an
owned temporary directory. The owner GDB socket's parent directory must have
mode 0700, and the socket itself is set to 0600. The control client must
complete version negotiation within `DEBUG_GATEWAY_STARTUP_TIMEOUT` (5 s).

### Wire protocol

Control frames use version 1 of the `CRDBGW1` framing:

```text
offset  size  field
0       8     magic "CRDBGW1\0"
8       2     protocol version (1), big-endian
10      1     message kind (closed tag)
11      1     flags, zero in version 1
12      4     stream id, big-endian; zero for connection control
16      4     payload length, big-endian
20      N     payload, at most DEBUG_GATEWAY_MAX_PAYLOAD (1 MiB)
```

| Tag | Kind | Purpose |
| --- | --- | --- |
| 1 / 2 | `Hello` / `HelloAck` | Negotiation; the acknowledgement payload is `debug-gateway.v1` |
| 3 / 4 / 5 | `BackendPrepare` / `BackendCommit` / `BackendAbort` | Two-phase backend replacement |
| 6 | `RspData` | RSP bytes |
| 7-11 | `ExecOpen`, `PtyOpen`, `SshOpen`, `ChannelData`, `ChannelClose` | Reserved; this gateway rejects them |
| 12 | `Ack` | Success |
| 13 | `RunControl` | Scheduler polls for and completes GDB run control |
| 14 / 15 | `BackendStatus` / `BackendStatusAck` | Active and prepared identities |
| 16 / 17 | `OperatorStatus` / `OperatorStatusAck` | Bound operator listener address |
| 18 | `SchedulerLease` | Acquire or release scheduler ownership around an internal run |
| 19 | `OperatorAccess` | `branch-guest-write`, admitted only on a private `unix:` operator endpoint |
| 255 | `Error` | `ProtocolViolation`, `InvalidRequest`, `BackendUnavailable`, `Unsupported`, or `Internal`, with bounded UTF-8 detail |

Every control connection must start with `Hello`. A malformed, truncated, or
disconnected control client closes only its own connection. The gateway
process and its active backend survive it.

### Backend replacement

`DebugGateway` holds an `active` and an optional `prepared` backend, each a
`QemuRspEndpoint` (an absolute Unix path with no NUL, CR, or LF) plus a
monotonic `BackendGeneration`.

- **Prepare.** The gateway connects to the candidate with
  `QEMU_RSP_TIMEOUT` (5 s) read and write timeouts. It sends `?` and requires
  an `S` or `T` stop reply, then replays the persistent `RspSessionState` and
  requires `OK` for each packet. That state is the last `Hg` and `Hc` thread
  selections and the installed `Z1` hardware breakpoints. If the GDB state
  changes during hydration, the gateway retries up to three times. Preparing
  the same endpoint again returns the same generation, so a lost
  acknowledgement is recoverable.
- **Commit.** Commit is refused unless the boundary is clean: no RSP response
  pending, no queued or in-flight run control, and no scheduler lease. It is
  also refused if the candidate was hydrated before the latest state change.
  Committing a generation that is already active returns success again.
  Commit swaps the backend under the same operator GDB connection and clears
  any branch guest-write grant.
- **Abort.** The candidate is dropped and the active backend and GDB state
  are left untouched.
- **Status.** A newly negotiated controller sends `BackendStatus` to learn
  the active and prepared generation and endpoint before it retries or
  reconciles.

Persistent RSP state is recorded only after QEMU returns a semantic `OK`, not
on a transport acknowledgement.

### RSP handling

`RspStreamDecoder` parses the operator byte stream incrementally into `+`,
`-`, interrupt (`0x03`), and checksum-validated `$...#xx` packets. Packets may
arrive split or coalesced. The decoder buffers at most
`RSP_MAX_BUFFERED_BYTES` (1 MiB), and any other leading byte fails closed.

`classify_rsp_packet` applies the canonical policy, allow-by-exception:

| Disposition | Packets | Reply |
| --- | --- | --- |
| `SchedulerRunControl` | `c`, `C`, `s`, `S`, `vCont;...`, interrupt | Routed to the session scheduler |
| `ForwardToQemu` | `?`, `g`, `p`, `m`, `T`, `H`, `Z0`/`z0` (as `Z1`/`z1`), `Z1`/`z1`, `vCont?`, `vMustReplyEmpty`, and the listed `q...` queries (`qSupported`, thread info, `qXfer` features and threads, `qC`, `qAttached`, `qOffsets`, `qSymbol`, `qCRC`, `qSearch:memory`, TLS address) | QEMU's reply |
| `RejectReadOnly` | `G`, `P`, `M`, `X`, `A`, `qRcmd,`, `vFlash` | `E22`, unless a branch guest-write grant is active |
| `RejectUnsupported` | Everything else, including `k`, `D`, `vKill`, `vFile`, `QStartNoAckMode`, `Z2`-`Z4` | `E01` |

Forwarded requests are bounded by `MAX_PENDING_RSP_REQUESTS` (64) and
`MAX_PENDING_RSP_BYTES` (64 KiB). Overflow, or a request that arrives while
run control is outstanding, is answered with `E20`.

Guest register and memory writes reach QEMU only after a non-canonical fork
has sent `OperatorAccess branch-guest-write` and only on a private Unix
operator endpoint. A backend commit revokes that grant.

### Scheduler-routed run control

No RSP packet can advance QEMU outside scheduler order. The gateway allows one
outstanding run-control request. In acknowledgement mode, it writes `+` to
GDB before the request becomes visible to scheduler polls. It tags the request
with a monotone id and the operator-connection epoch, and treats a
retransmitted duplicate as the same request. An interrupt replaces a queued
request.

The session actor polls `RunControl` between quanta and maps the packet to an
ordinary session command:

| Packet | Session command | Stop reply |
| --- | --- | --- |
| `0x03` | `Pause` | `T02` |
| `c`, `vCont;c` | `Continue` | `T05` |
| `s`, any `vCont` with an `s` action | `Step { mode: StepMode::Quantum }` | `T05` |
| Anything else | none | `E01` |

GDB's all-stop `vCont;s:<selected>;c:<others>` therefore means one
deterministic quantum. Raw QEMU single-instruction stepping is never exposed.
On the canonical run, these commands hit the branch gate and complete with
`E31`. The scheduler's stop packet is kept until GDB acknowledges it, and a
`-` retransmits the same bytes without forwarding anything to QEMU.

### Operator disconnect

When the operator's GDB disconnects cleanly, the gateway retires that
transport. It reconnects the same private QEMU endpoint, checks the paused
stop reply, and replays the acknowledged thread and breakpoint state before
it serves the next client. Recovery is impossible in three cases: a QEMU
response is still outstanding, a scheduler run is in flight, or the reconnect
fails. In each case the gateway deactivates the backend, and later RSP
requests are rejected until a replacement commits. A disconnect during a GDB
scheduler run interrupts that run without failing the session.

## Live runtime replacement

In the production daemon, `goto`, reverse-step, reverse-continue, and
`fork-debug` all replace the whole world behind the stable GDB connection.

1. At every completed scheduler boundary, the lifecycle samples each live
   node's execution fingerprint. These samples
   (`ProductionVmDebugRuntimeEvidence`) are sealed to the exact
   `RuntimeState`: configuration, event-log offset, scheduler state, node
   icounts, node times, and fingerprints.
2. A reposition request must name the gateway's active endpoint, the attached
   node, and the current configuration. Its target must have sealed evidence
   from the original live execution.
3. The lifecycle launches two independent whole-world replay candidates to
   the target. The two candidates must agree, and the selected candidate must
   also reproduce the original live evidence. Equal coordinates alone are not
   enough.
4. The gateway prepares and commits the candidate's private RSP endpoint.
   The previous world, graph, attach record, and GDB connection stay
   unchanged until commit. A failure before commit shuts the candidate down
   and leaves them in place.
5. After a successful promotion, the gateway is transferred to the candidate
   before the retired world loses scheduler authority. The retired world is
   then shut down. The report records `DebugRetiredWorldCleanup::Reaped`, or
   `DetachedCleanupPending` if process exit was not observed.

If a lost commit or abort acknowledgement leaves gateway ownership
indeterminate, the lifecycle retains the possibly selected candidate as
quarantined. It refuses further scheduler and debugger work until it observes
the gateway process terminate.

## Access control

`DebugCoordinator` (session-owned) tracks the debugger lifecycle as
`DebugCoordinatorState`: `Detached`, `Attaching`, `CanonicalReadOnly`,
`Repositioning`, `NonCanonical`, `Detaching`, or `Failed`. Authorization uses
five closed `DebugCapability` values:

| Capability | Grants |
| --- | --- |
| `Observe` | Reading session state and debugger observations |
| `Control` | Holding the exclusive controller lease |
| `Mutate` | Forking and mutating a non-canonical scenario |
| `Shell` | Opening guest exec, PTY, or SSH channels |
| `Admin` | Changing debugger policy and authorization |

A session has at most one controller lease (`DebugControllerLease`, a client
id plus a monotone generation). Stale generations are rejected on every
operation. Holding a capability never bypasses the branch gate.

Remote access uses the daemon's HTTP/2 transport with mutual TLS.
Per-certificate role mappings come from `serve --debug-role`. Cleartext
access requires `--trusted-unauthenticated-bind`. The CLI exposes the
daemon-side gateway through a client-side loopback relay, so GDB always
connects to a local address. Lease holders, acquisition tokens, and relay
ownership are described in [control-api.md](control-api.md); the session
actor is described in [session.md](session.md).

## Guest introspection

After `fork-debug`, an operator with `Shell` can run argv commands, a PTY, or
an SSH byte bridge inside the guest. These channels always target the guest,
never the daemon host.

**Activation.** A dormant guest agent costs instructions, so it must not run
on canonical execution. Every debug-capable launch includes a fixed
activation-only virtio-serial port named `org.aos.crucible.debug`, backed by
a Crucible-owned Unix stream. The endpoint is part of the content-addressed
launch topology (see [qemu-integration.md](qemu-integration.md)). No bytes
cross it before the fork. After the non-canonical fork marker commits,
`activate_debug_guest` writes the fixed `QMP_DEBUG_GUEST_ACTIVATION_TOKEN`
(`CRUCIBLE_DEBUG_AGENT_V1\n`). The session then waits up to
`GUEST_ACTIVATION_QUANTUM_LIMIT` (1024) scheduler quanta for the agent's
feature advertisement. If negotiation fails, the committed branch identity is
still returned. Callers cannot choose the device, the token, or the bytes.

**Data path.** All feature, command, stream, resize, exit, and close records
are `CRGI` v1 records carried in `CRGX` v1 doorbell exchanges. The guest
buffer is `GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES` (4608) long with a
16-byte header. The records move through the guest-introspection rings of
the shared-memory ABI. See [guest-host-channel.md](guest-host-channel.md)
and [shmem-abi.md](shmem-abi.md). No introspection payload crosses QMP, the
activation port, or the gateway: the gateway rejects its reserved channel
message kinds.

**Scheduling.** An open channel holds the scheduler-mediated debug run. The
session stays the only quantum driver and exchanges bounded records between
completed quanta. The attached runtime tuple is refreshed after every
quantum, so a later `goto` validates the actual live coordinate. A
reposition releases the run and performs the replacement. A successful
commit closes every active channel with a typed `ClosedChannel` error; a
pre-commit failure keeps the channel. Nothing is carried from one QEMU
instance to the next.

**Agent bounds.** `crucible-guest agent`
(`crates/crucible/crucible-guest/src/guest_introspection_agent.rs`) launches
children directly from argv, with no shell. Concurrent channels default to
`GUEST_INTROSPECTION_DEFAULT_MAX_CHANNELS` (8), with a hard limit of
`GUEST_INTROSPECTION_MAX_CHANNELS` (64). The pending response backlog is 64
records, and each reader hands off at most two 4096-byte chunks. Full queues
apply backpressure to child pipes.

**CLI side.** Each CLI acquisition derives a fresh nonzero channel id, and
the default response-idle deadline is 30 s (`--guest-idle-timeout`). With
`--record-transcript`, the CLI writes a `CRGT` v1 file. The file is created
exclusively, starts with the header `CRGT\x01\0\0\0`, holds direction-tagged
complete `CRGI` records, and is capped at 64 MiB. Transcripts belong to the
branch and never enter canonical artifacts.

## Source mapping and multi-vCPU

Crucible serves the machine and the virtual-time coordinate. It does not
serve source mapping. There is no symbol server and no DWARF parser in
Crucible (`DebugSymbolResolutionPolicy::no_symbol_server`). The operator's
GDB resolves functions, lines, and locals against debug info the operator
supplies. The `crucible` suite ships GNU GDB 17.2 and `gdbserver`, built
hermetically by `pkgs/tools/gdb.nix` with `--enable-targets=all`, Python
scripting, and TUI.

QEMU's gdbstub exposes each vCPU as a GDB thread. The gateway forwards thread
queries and persists `Hg`/`Hc` selections across backend replacement.
Multi-vCPU determinism comes from the round-robin TCG model (see
[qemu-plugin.md](qemu-plugin.md)). Every time-travel landing is a whole
configuration, so all of a node's vCPUs land at the same coordinate.

## CLI surface

`crucible debug` is a thin wrapper that holds no debug state.
`DebugCliSurfaceContract::canonical` fixes its surface:

| Group | Members |
| --- | --- |
| Coordinates | `--at`, `--at-event`, `--at-failure`, `--at-checkpoint` |
| Control | `--node`, `--gdb-listen`, `--read-only`, `--allow-mutate`, `--checkpoint-stride` |
| Verbs | `attach-gdb`, `fork-debug`, `goto`, `reverse-step`, `reverse-continue`, `exec`, `pty`, `ssh` |

The planner refuses `fork-debug`, `exec`, `pty`, and `ssh` without
`--allow-mutate`. It sets `raw_gdb_single_step_allowed: false`, and it
rejects a plan that fails `proves_t_dbg_8`. Executed debugger operations
require a live production-daemon session (`--session id:epoch:seed`).
Local artifact and savepoint targets are planned but not executed. Command
details and current limitations are in
[../../users/crucible/debugging.md](../../users/crucible/debugging.md), and
CLI routing is in [cli.md](cli.md).

## Checks

| Check | Covers |
| --- | --- |
| `checks.crucible.phase6.debugAttach` | Attach as `instantiate`, the four channel roles, private gateway mediation |
| `checks.crucible.phase6.readOnlyDebugInspection` | Observational-only inspection, byte-identical causal subsequence |
| `checks.crucible.phase6.canonicalDebugBreakpoint` | Out-of-band breakpoints, `Z0` to `Z1` rewrite, `--allow-mutate` refusal |
| `checks.crucible.phase6.debugTimeTravel` | `goto`, reverse grains, reverse-continue, bisection on oracle mismatch |
| `checks.crucible.phase6.debugScopedTimeTravel` | Per-node and whole-world travel, checkpoint cadence |
| `checks.crucible.phase6.debugNonCanonicalBranch` | Branch gating, fork marker, debug-edit script, oracle exclusion |
| `checks.crucible.phase5.sessionDebugTimeTravel` | Session debug commands and gdbstub backend capability |
| `checks.crucible.phase7.debuggerPackage` | Hermetic GDB package with Python and both target architectures |
| `checks.crucible.phase7.debuggerLiveArchitectures` | Packaged x86_64 and aarch64 QEMU under TCG with packaged GDB: RSP negotiation, repeated identical register reads, hardware-breakpoint insert and remove |

The gateway crate's own tests (`crates/crucible/crucible-qemu-debug-gateway/src/main/tests.rs`
and `tests/process_lifecycle.rs`) cover split and coalesced packets, queue
limits, lost prepare and commit acknowledgements, stale hydration, commit
barriers, and disconnect deactivation. The suite also ships an out-of-check
manual runner, the `crucible-debugger-live-matrix` wrapper around
`pkgs/tools/crucible/live-debugger-matrix.sh`. It drives the whole flow on
both architectures through the public daemon and CLI.
