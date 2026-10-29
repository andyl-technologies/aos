# Control API

The control API is the programmatic surface over the session control plane
(see [session.md](session.md)). It is two co-designed things that share one
message vocabulary:

1. An **in-process client** that reaches a same-process session actor through
   its mailbox and lock-free mirrors, with no serialization.
2. An **HTTP/2 RPC surface** that exposes the same vocabulary to out-of-process
   clients: a CLI talking to a daemon, a remote driver, or a conformance runner.

Both implement one `ControlClient` trait, so callers are transport-agnostic.
The API is a thin wrapper: every method maps to one session command, one read
of the lock-free mirror, one read of the reproduction log, or server-owned
registry data. It adds no control semantics of its own. Operator setup of the
daemon is covered in the [daemon guide](../../users/crucible/daemon.md).

## Crates

| Crate | Owns | Does not own |
|-------|------|--------------|
| `crates/crucible/crucible-control-api` | Request/response values, the RPC ABI encoder and golden vectors, the open-set payload model, the API-to-session mapping table, the responsiveness contract | Servers, actors, QEMU |
| `crates/crucible/crucible-control-client` | `ControlClient`, `RpcControlClient` (HTTP/2 over `reqwest` with prior knowledge, optional mutual TLS), RPC stream decoders, local stream traits | Server or QEMU realization code |
| `crates/crucible/crucible-control-server` | `LifecycleControlPlane` (the session registry), in-process streaming adapters, the `axum` HTTP/2 server, mutual TLS, debugger authorization, the debug relay and gateway | Production QEMU lifecycle composition |
| `crates/crucible/crucible-daemon` | Production composition: QEMU lifecycle loops, campaign services, and the daemon-side responsiveness route | Wire contracts |

```text
  callers                         ControlClient            transport            session
  ----------------------------    ---------------------    -----------------    ----------------
  crucible CLI, drivers,     -->  InProcessLifecycleClient  (mailbox, mirror) -->  SessionActor<L>
  conformance tests               RpcControlClient  ---> HTTP/2 text RPC ---> LifecycleControlPlane
                                                          (axum server)          -> SessionActor<L>
```

`ControlWireModel::current()` is the shared serialized model for every
transport: it pins `RPC_PROTOCOL_VERSION` and the advertised open-set payload
kinds, and encodes `Hello` messages with the canonical ABI encoder.
`ControlTransportKind` is `InProcess` or `Http2Rpc`.

## Service surface

`ApiMethod::ALL` is the closed method set. `API_METHOD_MAPPINGS` classifies
each method by its thin dispatch route:

| Method | `ApiDispatch` | Session operation |
|--------|---------------|-------------------|
| `Hello` | `ServerObservation` | none; version negotiation and capability catalog |
| `ListScenarios` | `ServerObservation` | none; scenario registry |
| `CreateSession` | `SessionCreate { startup: Start }` | new actor, `Start` (then `Continue` unless `start_paused`) |
| `ListSessions` | `LiveMirrorRead { query: Status }` | lock-free mirror of each live session |
| `DestroySession` | `SessionCommand { command: Stop }` | acknowledged `Stop`, then actor shutdown and join |
| `GetReproduction` | `ReproductionLogRead` | actor-owned reproduction log |
| `Control` | `ControlStream { OneSessionCommandPerEnvelope }` | attach, then one command per envelope |
| `Watch` | `WatchStream { attach_query: Status }` | read-only attach: mirror snapshot plus event-log tail |
| `Send` | `SendEnvelope { OneSessionCommandPerEnvelope }` | one command per unary request |

`validate_thin_api_mapping` rejects a missing or duplicated method, a
browser-shaped request (`ApiRequestShape` has only `TypedProgrammatic`), a
dispatch that is not a thin wrapper (`ApiDispatch::is_thin_wrapper`), and a
session command kind without exactly one API command name.

`API_COMMAND_MAPPINGS` names every `SessionCommandKind`: `start`, `continue`,
`pause`, `step-quantum`, `step-event`, `step-assertion`, `step-timer`,
`step-duration`, `stop`, `exhaust-budget`, `set-breakpoint`, `remove-breakpoint`,
`create-savepoint`, `fork`, `query`, `attach-gdb`, `debug-goto`,
`debug-reverse-step`, `debug-reverse-continue`, `debug-fork-non-canonical`, and
`guest-introspection`.

`validate_control_watch_send_equivalence` checks that `Control` and
`Watch`+`Send` are both thin streaming wrappers and that their command
capability sets are identical and cover `SessionCommandKind::ALL`. A client that
does not want a bidirectional stream loses nothing by using `Watch` plus `Send`.

The server also exposes `ResumeSession` (authenticated campaign resume into a
new session) and debugger routes. Those are documented in
[time-travel-debugging.md](time-travel-debugging.md); campaign resume inputs are
owned by the campaign pages.

### HTTP/2 routes

Every route is `POST` with a canonical text body (see below).

| Path | Handler |
|------|---------|
| `/crucible.rpc/hello` | `Hello` |
| `/crucible.rpc/list-scenarios`, `/list-sessions` | Registry reads |
| `/crucible.rpc/create-session`, `/resume-session`, `/destroy-session` | Lifecycle |
| `/crucible.rpc/get-reproduction` | Reproduction context |
| `/crucible.rpc/control/attach` | `Control` attach; streaming response |
| `/crucible.rpc/control/send` | `Control` command envelope |
| `/crucible.rpc/watch` | `Watch` attach; streaming response |
| `/crucible.rpc/send` | `Send` |
| `/crucible.rpc/debug/...` | Controller lease, attach, goto, reverse step/continue, relay, guest exchange and fork |

Over HTTP/2, `Control` is an attach stream plus `control/send` posts; both send
routes share one handler, which is the concrete form of the Control/Watch+Send
equivalence.

## RPC ABI

The RPC ABI is one of Crucible's versioned boundary ABIs, alongside the shared
memory and control protocol ABIs (see [shmem-abi.md](shmem-abi.md) and
[control-protocol.md](control-protocol.md)). It is owned by
`crates/crucible/crucible-control-api/src/rpc_abi.rs`.

### Version and negotiation

```rust
pub const RPC_PROTOCOL_MAJOR: u16 = 8;
pub const RPC_PROTOCOL_MINOR: u16 = 0;
pub const RPC_PROTOCOL_PATCH: u16 = 0;
pub const RPC_PROTOCOL_BUILD: &str = "crucible-rpc-abi-v8";
```

Version 8 carries exact event ticks and optional raw retired-instruction
witnesses on events. A `ProtocolVersion` renders as
`major.minor.patch+build`, for example `8.0.0+crucible-rpc-abi-v8`. Major bumps
mark wire-incompatible changes, minor additive changes, patch compatible fixes.

Negotiation is exact. `negotiate_rpc_protocol(peer)` returns
`RpcAbiError::ExactVersionMismatch` for any peer version that differs from
`RPC_PROTOCOL_VERSION` in any field, including the build identifier, before any
message-specific decoding. A deployed build admits only itself; client and
server detect a mismatch in `Hello` and refuse rather than mis-decode.

### Message encoding

Bodies use the content type `application/vnd.crucible.rpc`. Each message is a
header line naming the message, followed by `key=value` lines in a fixed order:

```text
crucible.rpc/send-request
session-id=7
epoch=3
seed=<hex>
expected-epoch=3
command-id=42
command=crucible.cmd.pause
```

Free-form strings (messages, attribute names) are hex-encoded so that a value
can never inject a line. Optional values use the literal `none`. Streaming
responses (`Control` and `Watch`) concatenate messages, each terminated by an
empty line; the client splits on the blank-line separator
(`read_next_framed_rpc_message`).

Message headers in use include `hello-request`/`hello-response`,
`create-session-request`/`-response`, `resume-session-request`/`-response`,
`list-scenarios-request`/`-response`, `list-sessions-request`/`-response`,
`destroy-session-request`/`-response`, `get-reproduction-request`/`-response`,
`attach-request`, `attached-response`, `send-request`/`send-response`,
`event-frame`, `state-update-frame`, the debugger request/response pairs, and
`error`.

A streamed event frame:

```text
crucible.rpc/event-frame
generation=0
cursor=12
next-cursor=13
sequence=12
virtual-time-ticks=4096
stamp-tick=4096
stamp-retired=none
stamp-node=none
source=...
level=...
observational=false
kind=crucible.event....
attribute=<hex name>|<typed value>
```

A typed error:

```text
crucible.rpc/error
status=invalid-state
reason=epoch-mismatch
...detail lines...
```

### Golden vectors

`GOLDEN_RPC_VECTORS` (`.../rpc_abi/golden.rs`) is a frozen corpus of canonical
envelopes in stable conformance order, each with its structured
`RpcGoldenVectorMessage` and exact bytes: `hello-request`, `hello-response`,
`attached`, `attached-with-reproduction`, `get-reproduction-request`,
`get-reproduction-response`, `send-request`, `send-request-set-breakpoint`,
`send-response`, `send-response-set-breakpoint`,
`send-response-breakpoint-firings`, `send-response-rejected-not-found`,
`rpc-error-invalid-state`, `rpc-error-resource-limit`, and
`event-effect-applied`. `encode_rpc_message` must reproduce every vector byte for
byte, and `crates/crucible/crucible-control-api/tests/gate_abi_conformance.rs`
checks it under `gate:abi-conformance`.

`GOLDEN_VECTOR_RPC_PROTOCOL_VERSION` records the version the corpus was
generated for, and compile-time assertions tie its major, minor, and patch to
`RPC_PROTOCOL_VERSION`. The rule is `GOLDEN_VECTOR_RPC_REGENERATION_RULE`:
regenerate every RPC golden vector whenever `RPC_PROTOCOL_VERSION` changes. An
unintended wire change therefore fails to compile or fails the gate.

## Open-set payloads

The envelope, event source set, run-state machine, and session identity are
closed. Payloads are open: commands, breakpoint conditions, and events are each a
dotted `kind` string plus a typed attribute map
(`crates/crucible/crucible-control-api/src/open_set.rs`):

```text
kind = "crucible.event.rng_draw"
attributes.stream_name = "scheduler"
attributes.value = uint(17)
```

| Category | Prefix | Source of kinds |
|----------|--------|-----------------|
| Command | `crucible.cmd.` | `API_COMMAND_MAPPINGS` (`crucible.cmd.<command-name>`) |
| Breakpoint | `crucible.bp.` | The shared predicate vocabulary (`crucible.bp.at`, `crucible.bp.node-state`, `crucible.bp.all-of`, ...) |
| Event | `crucible.event.` | The engine's event-kind catalog |

`Hello` advertises the categories as `OPEN_SET_CAPABILITY_CATEGORIES`
(`crucible.cmd.*`, `crucible.bp.*`, `crucible.event.*`), also exported as
`RPC_OPEN_SET_PAYLOAD_KINDS`. Attribute values are `Bool`, `Int`, `Uint`,
`Uint128`, `Float64Bits` (an exact IEEE-754 bit pattern), `String`, and `Bytes`,
so consumers read fields by name and type instead of scraping strings.

Event payloads on the wire use the same kind strings and attributes as the
event log (see [event-log.md](event-log.md)); there is no parallel API event
vocabulary. `open_set_event_envelope_from_entry` converts a
`SchedulerEventLogEntry` into an envelope carrying sequence, the exact
virtual-time stamp, source, level, an `observational` flag derived from
`SchedulerEventLogClass`, and the payload.

Compatibility rules are asymmetric:

- **Receive.** `receive_open_set_event_payload` never rejects. A kind that is
  not in the catalog is returned as `ReceivedOpenSetEventPayload::Opaque`
  carrying its kind and attributes, so an older client survives a newer server.
- **Send.** `validate_open_set_send_payload` rejects an unknown command or
  breakpoint kind with `OpenSetPayloadError::UnsupportedKind` and a known kind
  with an undeclared attribute with `OpenSetPayloadError::InvalidArgument`, so a
  client can detect an unsupported kind before sending it.

## Streaming

`Control` and `Watch` deliver the session's one event log as a cursor: replay
from the requested position to the tail observed at attach, then the live tail.

### Attach and snapshot-on-attach

`AttachRequest { session, expected_epoch, from, client_name }` attaches at
`from: EventLogCursor`. The server-side attach
(`crates/crucible/crucible-control-server/src/streaming.rs`) does, in order:

1. Validate the session reference and optional epoch guard.
2. Subscribe to the state-transition bus.
3. `subscribe_with_replay_tail(from)` on the session event log, capturing the
   attach tail.
4. Build an `AttachSnapshot` with `snapshot_through(attach_tail)` and the
   reproduction records whose `at_sequence` is at or before the tail.
5. Read the lock-free mirror and set the state stream's sequence floor to the
   mirror's `state_transition_sequence`, so transitions already reflected in the
   attach state are not delivered again.

The reply is `Attached { session, event_log_len, state, version, capabilities,
snapshot }`. The snapshot (`through`, `event_count`, `causal_event_count`,
`observational_event_count`, `last_sequence`, `reproduction`) is entirely
derivable by replaying the log to the attach cursor; it is an optimization so a
fresh client can render without folding the whole log, never a second source of
truth.

Cursor semantics follow from the session stream (see
[session.md](session.md#event-log-stream)): `from = 0` replays the whole log, a
cursor beyond the tail skips historical replay, replay is delivered in bounded
batches, and a subscriber that lags the bounded live tail resumes from the
retained log rather than back-pressuring the actor. Each `StreamingEventFrame`
carries `generation`, `cursor`, `next_cursor`, and the open-set event envelope.

The causal subsequence of the stream is deterministic for a given scenario,
seed, and schedule. Observational entries also flow, flagged `observational`,
so an interactive viewer can show them and a determinism comparison can drop
them. Attaching, replaying, or detaching never changes the run.

### State updates

Run-state changes are not event-log entries, so they are delivered as distinct
`StreamingStateUpdateFrame { sequence, update: StateUpdate { session, state } }`
frames, encoded as `crucible.rpc/state-update-frame`. `recv_frame` multiplexes
event and state frames; `recv_state_update` reads state only. Sequences are
monotone. A lagging state subscriber has superseded updates coalesced to the
newest one, which is safe because a later state supersedes an earlier one. A
`Watch`-only client can track run-state purely from these frames plus the
`state_update` field of `SendResponse`.

## Command dispatch and status taxonomy

`Send` and each `Control` envelope dispatch exactly one session command
(`dispatch_command` in `crates/crucible/crucible-control-server/src/streaming.rs`):

1. Read the mirror and evaluate `lifecycle_transition(state, kind)`. A
   `Rejected` transition returns `Rejected { InvalidState }` without touching the
   actor.
2. Wrap the command with `SessionCommand::acknowledged(command, ...)` and a
   reply observer, and send it. Wrapped rejections are recoverable, so a rejected
   command never stops the session.
3. Await the actor's reply. Typed replies (breakpoint id, savepoint info, query
   result) populate `SendResponse`.
4. If the accepted transition changes run-state, wait for the mirror to publish
   it, polling with `tokio::task::yield_now` for at most
   `STREAMING_COMMAND_MAX_ACTOR_YIELDS` (128) yields. `Continue` also accepts a
   later `Paused` or `Stopped` state when its `state_transition_sequence` is newer
   than the pre-command snapshot, because a breakpoint or terminal condition can
   follow `Running` before the observer samples; a stale `Paused` mirror does not
   acknowledge `Continue`. Step commands report their expected state without
   waiting for a stable one.

`SendResponse` carries `result: CommandResult { command_id, command_kind,
status }`, an optional `state_update`, and optional `query_result`,
`breakpoint_id`, and `savepoint_info`. An accepted lifecycle `Stop` also returns
the terminal `Snapshot` captured before cleanup.

Rejections use the closed `CommandRejectionKind` set, which maps one-to-one onto
`RpcStatusCode` (`rpc_status`, and `TryFrom<RpcStatusCode>` for all codes but
`Ok`):

| `CommandRejectionKind` | `RpcStatusCode` wire name | Typical session cause |
|------------------------|---------------------------|------------------------|
| `InvalidState` | `invalid-state` | `InvalidTransition`, `InvalidEngineState`, debugger attach or branch required |
| `NotFound` | `not-found` | `BreakpointNotFound`, unrecorded checkpoint, unknown debug coordinate |
| `InvalidArgument` | `invalid-argument` | Breakpoint prefix errors, schedule-prefix errors, rejected backend input |
| `Unsupported` | `unsupported` | Unsupported breakpoint action or fault, `BackendError::Unsupported` |
| `Internal` | `internal` | Event-log offset and control-replay faults, scheduler boundary faults |

The mapping lives in `session_error_rejection_kind` and its engine, scheduler,
and backend helpers. A `RemoveBreakpoint` that reports `Ok(false)` is converted to
`NotFound`. On the wire an accepted command has `status=accepted` and a
rejection `status=rejected:<wire-name>`. `rpc_status_code_wire_name` and
`rpc_status_code_from_wire_name` are the only spellings.

Lifecycle failures use the same status codes in a `crucible.rpc/error` body with
an HTTP status:

| Error | HTTP | `status` / `reason` |
|-------|------|---------------------|
| Epoch mismatch (lifecycle) | 412 | `invalid-state` / `epoch-mismatch`, with `session-id`, `expected`, `actual` |
| Epoch mismatch (streaming) | 412 | `invalid-state` / `streaming-epoch-mismatch` |
| Unknown session | 404 | `not-found` / `lifecycle-session-not-found` or `streaming-session-not-found` |
| Session limit reached | 429 | `invalid-state` / `session-limit` |
| Read-only server rejects a mutation | 403 | `unsupported` / `read-only` |
| Streaming internal faults | 500 | `internal` / `internal` |

## Session identity and epoch guards

A `SessionRef` is `(id: SessionId, epoch: u64, seed: Seed)`. Session ids and
epochs are allocated by the `LifecycleControlPlane`, both starting at 1; every
`CreateSession` and `ResumeSession` takes the next epoch
(`self.next_epoch = self.next_epoch.saturating_add(1)`), so a session id that is
recreated always has a new epoch.

Every attach, `Send`, `DestroySession`, and `GetReproduction` checks the
reference's epoch against the live session and also accepts an optional
`expected_epoch` (`with_expected_epoch`). Any mismatch fails fast with
`LifecycleApiError::EpochMismatch` or `StreamingApiError::EpochMismatch` before
dispatch, so a command cannot land on a recycled incarnation, and neither the
session state nor its event-log cursor changes.

Session identity is closed protocol data and host bookkeeping only. The epoch
never enters `State` or the causal event log; two runs that differ only in the
epoch the server assigned produce identical causal subsequences.

`DestroySession` is idempotent: destroying an absent id returns
`already_absent: true`. For a live session it sends an acknowledged `Stop`, then
a second acknowledged `Stop` to release a terminal keepalive, and joins the actor
task.

## Reproduction context

The session's boundary-control log (see
[session.md](session.md#boundary-deferred-application)) is mirrored into a
`SessionReproductionLog` by the actor (`sync_reproduction_log`) and exposed to
clients two ways: in every `AttachSnapshot::reproduction`, and through the
unary `GetReproduction`. Reading it is read-only: it neither appends to nor
truncates the event-log stream.

```rust
pub struct ReproductionCommandRecord {
    pub sequence: u64,                       // contiguous from 1
    pub payload: ReproductionCommandPayload, // command kind, reply-free
                                             // command_payload material,
                                             // scheduler_batch, scheduler_control
    pub virtual_time: VirtualTime,           // boundary where it took effect
    pub quanta: u64,
    pub at_sequence: u64,                    // event-log sequence before it ran
    pub result: ReproductionCommandResult,   // Accepted
    pub observational_order: u64,            // ordering aid only; == sequence
}
```

Each record is keyed by the virtual-time boundary at which it took effect,
never by wall-clock time. `observational_order` exists to order same-boundary
commands for display and is not a replay input. `TryFrom<ReproductionCommandRecord>`
for `SessionControlLogEntry` decodes a record back into the session log and
rejects zero sequences, an `observational_order` that differs from the
sequence, and batch/control mismatches. Re-applying the stream at the same
boundaries reproduces an interactively driven run, and an interactive run and a
scripted run of the same schedule produce equivalent contexts.

## Nondeterminism: the API does not perturb the run

Transports, observers, and wall-clock gaps are not simulation inputs. The
evidence is
`api_nondeterminism_gate_proves_transport_observers_wall_clock_and_read_only_traffic_do_not_perturb_state`
in `crates/crucible/crucible-control-client/tests/gate_control_client/contract_tests/transport_conformance.rs`.
It drives the same lifecycle through the in-process client and through the
HTTP/2 client, each with quiet traffic and with noisy traffic (extra `Hello`,
`ListScenarios`, snapshot queries, attached `Control` and `Watch` observers, and
simulated wall-clock gaps with no scheduler input), plus RPC request arrival
permutations, and requires identical normalized projections (final event count,
causal and observational counts, last sequence) and identical streamed causal
subsequences. Read-only traffic must be schedule-neutral.

## Control responsiveness contract

`crates/crucible/crucible-control-api/src/control_responsive.rs` expresses
`gate:control-responsive` purely in quanta; wall-clock durations are absent from
its data model. Callers supply `ControlOperationAcknowledgement` records
(operation, requested state, requested and acknowledged quantum counts, applied
or rejected) from an in-process client, an RPC route, or a daemon route.
`validate_control_responsiveness` requires each `CONTROL_RESPONSIVE_REQUIRED_OPERATIONS`
operation (`Pause` and `Query`) to be issued against a running session and
acknowledged within `CONTROL_RESPONSIVE_QUANTUM_BOUND` (1) quantum, with quantum
counts that never move backward. The daemon forwards to the same validator
(`DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND` in
`crates/crucible/crucible-daemon/src/control_responsiveness.rs`); it defines no
separate responsiveness rule.

## Server: `LifecycleControlPlane`

`LifecycleControlPlane<L, F>` (`crates/crucible/crucible-control-server/src/lifecycle.rs`)
is the session registry. It holds the scenario catalog, a `BTreeMap` of live
`SessionRuntime`s (mailbox sender, `LiveSnapshot`, event-log hub, reproduction
log, state-transition bus, debugger coordinator, actor task), the id and epoch
counters, and a loop factory `F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed)
-> Result<L, LifecycleApiError>`. Construction failures from the factory surface
as `LifecycleApiError::LoopFactory`; there is no silent fallback to a test loop.

`create_session` resolves the scenario (named catalog entry, or an inline form
whose seed must equal the request seed), bakes genesis into a temporal graph,
builds the engine and actor with a mailbox of
`LIFECYCLE_SESSION_MAILBOX_CAPACITY` (16), spawns `actor.run()`, and sends
`Start` (and `Continue` unless `start_paused`), waiting at most
`LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS` (128) yields for each state to
appear in the mirror. A failed startup cleans up the actor before returning.

## Serving

`serve_lifecycle_http2*` and `serve_shared_lifecycle_http2*`
(`crates/crucible/crucible-control-server/src/server.rs`) bind an `axum` router
over a caller-supplied listener. The `crucible serve` command composes them with
a control plane; see [cli.md](cli.md#serve).

### Multiple clients

The control plane is shared as `Arc<tokio::sync::Mutex<LifecycleControlPlane>>`.
Unary calls and sends take the lock for the duration of one dispatch, which is
bounded by the actor-yield budget. Streams hold the lock only to attach; after
that, events and state updates come from the session's broadcast hubs and
mirrors, so any number of `Watch` clients observe a run without entering the
stepping path or blocking each other.

### Session cap

`with_max_sessions(n)` caps live sessions. `create_session`, resume, and
read-only admission return `SessionLimitReached { limit }` (HTTP 429,
`session-limit`) once `n` sessions are registered. Destroying a session frees its
slot.

### Read-only mode

`LifecycleServerMode::read_only()` rejects every state-mutating call at the HTTP
layer with 403, `status=unsupported`, `reason=read-only`: `create-session`,
`resume-session`, `destroy-session`, `control-attach`, and any `send` whose
command is not `SessionCommand::is_read_only` (queries and observation-only
debugger repositioning). `Hello`, the list calls, `GetReproduction`, and `Watch`
remain available. Separately, sessions admitted as exclusive read-only debug
sessions reject everything but `Query` and `Stop` with
`LifecycleApiError::ReadOnlySession`.

### Shutdown

The `*_until_shutdown` variants run `axum::serve(...).with_graceful_shutdown`.
When the caller's shutdown future resolves, the server stops accepting
connections and flips a `watch` channel that every streaming response observes:
`Watch` and `Control` bodies end at the next frame boundary instead of holding
the connection open. Mutual-TLS servers bound shutdown with a 10 second grace
period.

### Transport security and limits

`mutual_tls_acceptor_from_pem` builds a `rustls` acceptor that requires client
certificates from a configured CA. Each authenticated connection gets a
`DebugTransportIdentity` (the SHA-256 fingerprint of the leaf certificate) used
by `DebugAuthorizationPolicy`, which grants nothing by default. Cleartext serving
exists only for explicitly trusted listeners.

| Limit | Value |
|-------|-------|
| Concurrent TLS connections | 256 |
| TLS handshake timeout | 10 s |
| Small RPC body (hello, lists, attach, lifecycle) | 64 KiB |
| `create-session` body | 64 MiB |
| `send` body | 16 MiB |
| `resume-session` body | 512 MiB envelope plus twice the replay-closure and observation-source caps |
| Aggregate in-flight request bodies | 1 GiB (semaphore) |
| Body read timeout | 15 s |

Each body class has a fixed envelope so a single request cannot grow with
available process memory.

## Tests

| Check or target | Guards |
|-----------------|--------|
| `checks.crucible.phase5.apiControlClient`, `apiReferenceClientConformance` | The shared client trait and the full lifecycle against both transports |
| `checks.crucible.phase5.apiSessionCommandMapping`, `apiStreamingEquivalence` | Thin mapping and Control/Watch+Send equivalence |
| `checks.crucible.phase5.apiLifecycleUnary` | Unary lifecycle methods |
| `checks.crucible.phase5.apiOpenSetPayload` | Open-set kinds, opaque receive, send validation |
| `checks.crucible.phase5.apiStreamingCursor`, `apiStateUpdateStream` | Replay then live tail, snapshot-on-attach, state frames |
| `checks.crucible.phase5.apiEpochGuards` | Epoch allocation and fast-fail guards |
| `checks.crucible.phase5.apiReproductionContext` | Reproduction records on attach and `GetReproduction` |
| `checks.crucible.phase5.apiCommandStatusTaxonomy` | Rejection kinds and status codes |
| `checks.crucible.phase5.apiNondeterminism` | Transport and observer neutrality |
| `crates/crucible/crucible-control-api/tests/gate_abi_conformance.rs` | Golden vectors (`gate:abi-conformance`) |
| `crates/crucible/crucible-control-server/tests/gate_*.rs` | Epoch guards, streaming cursor and equivalence, reproduction context, responsiveness |
| `crates/crucible/crucible-daemon/tests/gate_control_responsive.rs` | Daemon-routed responsiveness |
