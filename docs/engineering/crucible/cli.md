# CLI internals

The `crucible` binary (`crates/crucible/crucible-cli`, `[[bin]] name = "crucible"`)
is a thin client over the session control plane (see [session.md](session.md)),
the control API (see [control-api.md](control-api.md)), and the campaign
service. This page covers how it is built: dispatch planning, backend
selection and routing, hermetic QEMU discovery, seed handling, output, exit
status, and completions. The user-facing command and flag reference is
[reference.md](../../users/crucible/reference.md); operator guides are under
[`docs/users/crucible/`](../../users/crucible/README.md).

## Code map

| Path | Owns |
|------|------|
| `crates/crucible/crucible-cli/src/main.rs` | Clap definitions (`Cli`, `Commands`, per-command `Args`), `CliThinWrapperPlan`, `plan_cli_invocation` |
| `.../cli/dispatch.rs` | Process entry, parse-error exit codes, the dispatch pipeline |
| `.../null_operation_recorder.rs` | `execute_cli_dispatch_plan` and the null recorder |
| `.../cli/backend.rs` | `BackendSelectionPlan`, QEMU/plugin discovery and validation, local runners |
| `.../cli/backend/routing.rs` | `execute_backend_routed_command`, the local/remote split |
| `.../cli/backend/evidence.rs` | Route consistency and execution-evidence checks |
| `.../cli/backend_outcome.rs` | `BackendCommandStatus`, outcome projection |
| `.../cli/planning/` | Invocation plans, seed resolution, trace-format validation, the wall-clock guard |
| `.../cli/resume/remote.rs` | Daemon RPC client construction and remote workflows |
| `.../cli/control/` | Save, interactive control, and event-stream draining over `ControlClient` |
| `.../cli/verify_serve/service.rs` | `crucible serve` host setup, shutdown, campaign attachments |
| `.../cli/replay.rs` | `emit_canonical_trace` and replay flows |
| `.../cli/report/error.rs` | `CliError` and its exit-code mapping |
| `.../cli/dispatch/support.rs` | `write_completions` and selftest helpers |

All `.../cli/` paths are under `crates/crucible/crucible-cli/src/`.

## Thin-wrapper design

The CLI parses intent, routes it to a backend, and renders results. It does
not schedule, fork, materialize checkpoints, or own canonical run state; those
belong to the session, the execution graph, and the scheduler. Anything it needs
across invocations is a content-addressed store reference, a reproduction
artifact, a savepoint handle, a findings ledger, a debug coordinate, or a daemon
connection, never a second source of truth for a run.

This is enforced in code rather than by convention. `plan_cli_invocation(cli)`
builds a `CliThinWrapperPlan` for every subcommand before anything runs:

```rust
struct CliThinWrapperPlan {
    subcommand: CliSubcommand,
    session_commands: Vec<SessionCommandKind>,
    api_calls: Vec<CliApiCall>,
    delegated_drivers: Vec<CliDelegatedDriver>,
    state_references: Vec<CliStateReferenceKind>,
    thin_wrapper: bool,
    owns_canonical_run_state: bool,
    implements_scheduler: bool,
    implements_checkpoint_materialization: bool,
    extra_control_capabilities: Vec<&'static str>,
}
```

`execute_cli_dispatch_plan` fails the invocation with "CLI invocation violates
the thin-wrapper contract" unless the plan is a thin wrapper that owns no
canonical run state, implements no scheduler or checkpoint materialization,
adds no extra control capabilities, delegates to at least one driver, holds only
non-canonical state references, uses only `SessionCommandKind::ALL` commands
and `CliApiCall::ALL` calls that name a `ControlClient` method, and decomposes
into at least one session command or API call (or is a delegated-only command
such as `triage`, `campaign`, `store`, or `completions`).

| Subcommand | Session commands | API calls | Delegated drivers |
|------------|------------------|-----------|-------------------|
| `run` | Start, Continue, Query, Stop | Hello, CreateSession, WatchAttach, SendCommand, GetReproduction | SessionControlPlane |
| `verify` | Start, Continue, Query | Hello, CreateSession | SessionControlPlane, ReplayOracle |
| `selftest` | Start, Continue, Query | none | HarnessGateCatalog |
| `save` | Start, StepQuantum, StepDuration, SetBreakpoint, CreateSavepoint, Stop, Query | Hello, CreateSession, SendCommand | SessionControlPlane, ReplayOracle |
| `resume` | StepQuantum, StepDuration, Continue, Stop, Query | Hello, CreateSession, SendCommand | SessionControlPlane |
| `replay` | Start, Continue | none | SessionControlPlane, ReplayOracle |
| `search`, `fuzz` | Start, Continue, Fork, Query | Hello, CreateSession, SendCommand | ExplorationEngine, ReplayOracle |
| `triage` | none | none | TriageEngine |
| `debug` | Query, AttachGdb, DebugGoto, DebugReverseStep, DebugReverseContinue, DebugForkNonCanonical | Hello, ListSessions, SendCommand | SessionControlPlane, TimeTravelDebugger |
| `serve` | Start, Continue, Stop, Query | all | DaemonHost, ControlApi |
| `campaign` | none | none | CampaignService |
| `store` | none | none | StoreMaintenance |
| `completions` | none | none | ShellCompletionGenerator |

With `--daemon`, every backend-selecting subcommand also gains the `ControlApi`
driver and a `DaemonConnection` state reference. `triage` is routed to the
campaign service as a campaign triage request.

## Dispatch pipeline

`dispatch(cli)` (`.../cli/dispatch.rs`) runs these steps in order:

1. Validate the thin-wrapper plan.
2. Route `campaign`, `triage`, and `store` to their service invocations.
3. Plan determinism ergonomics (seed resolution and trace format), then
   per-command invocation plans (`plan_run_invocation`, `plan_save_invocation`,
   and so on).
4. Print the seed announcement when human output is enabled.
5. Hand `serve` to `run_serve_invocation`.
6. Plan backend selection and execute the routed command.
7. Emit the canonical trace and map the outcome to an exit status.

The binary also doubles as the canonical planner worker: if its first argument
is `crucible_daemon::CANONICAL_PLANNER_WORKER_ARGUMENT`, it serves one planner
process exchange over stdin/stdout and exits (status 2 for unexpected extra
arguments, 3 for worker failure) without parsing the normal CLI.

## Backend selection and routing

`plan_backend_selection` runs for `run`, `verify`, `save`, `resume`, `replay`,
`search`, `fuzz`, `debug`, and `serve`, producing a `BackendSelectionPlan`:

```text
--daemon set?
  yes -> RemoteDaemon: no local backend; RPC over the control API
         - serve + --daemon is a usage error
         - requires either complete --daemon-ca/--daemon-cert/--daemon-key
           mutual TLS or --trusted-unauthenticated-daemon (never both)
  no  -> Local, by --backend:
         qemu   -> require hermetic QEMU + plugin discovery (fail closed)
         auto   -> QEMU if discovered; otherwise fail closed in production
         double -> in-process SimDouble (test-double builds only)
```

The `Double` backend value exists only when the crate is built with `test` or
the `test-double` feature; production builds expose `auto|qemu`
(`BACKEND_VALUE_NAME`), and production `auto` never degrades to the double. The
packaged derivation checks that the installed `crucible --help` does not list
`auto|qemu|double`.

`execute_backend_routed_command` (`.../cli/backend/routing.rs`) refuses to run
unless the thin-wrapper plan is valid, the backend plan is internally
consistent (`has_consistent_route`: a remote plan has a non-empty daemon, no
resolved backend, and uses the control API; a local plan has a resolved backend
matching the requested value and reason), and both plans name the same
subcommand. It then calls `run_local` or `run_remote` and checks the produced
`BackendExecutionEvidence` against `expected_execution_evidence`: local QEMU
runs must report the discovered build id and plugin ABI, remote runs the daemon
address.

Local and remote paths share their workflows. The run, save, resume, and verify
workflows are generic over `ControlClient`: a remote invocation passes an
`RpcControlClient` built by `remote_rpc_client` (a bare `host:port` becomes
`http://host:port`; mutual TLS concatenates the client certificate and key
PEM), and local double runs pass an `InProcessLifecycleClient`. Local production
QEMU runs go through guarded campaign execution; `--campaign-deployment`
selects that local path and is rejected together with `--daemon`. Because both
routes drive the same session through the same client trait, a local run and a
daemon run of the same command differ only in connection errors and backend
fidelity.

Unless `-q` or a machine format is in effect, the CLI announces the resolved
backend, for example `crucible: backend = qemu (--backend auto; patched QEMU and
plugin discovered)` or `crucible: backend = daemon (remote API ...)`.

## Hermetic QEMU discovery

A QEMU-backed run needs the patched QEMU system binary and the matching
`crucible-qemu-plugin` shared object. Using whatever QEMU happens to be on the
host would silently break patch-dependent determinism and inertness, so
discovery is hermetic and fails closed.

Each artifact is located independently, first match wins
(`select_qemu_discovery_candidate`):

| Order | Source | `QemuDiscoverySource` |
|-------|--------|------------------------|
| 1 | `--qemu` / `--plugin` | `Flag` |
| 2 | `CRUCIBLE_QEMU` / `CRUCIBLE_PLUGIN` (non-blank) | `Environment` |
| 3 | `CRUCIBLE_AOS_QEMU` / `CRUCIBLE_AOS_PLUGIN`, baked in at compile time with `option_env!` | `AosPackageSet` |

The host `$PATH` is never consulted. The packaged `crucible` wrapper
(`pkgs/tools/crucible/crucible.nix`) defaults `CRUCIBLE_QEMU` to the
`qemu-crucible` system binary for the native architecture and `CRUCIBLE_PLUGIN`
to `libcrucible_qemu_plugin.so` from the matching plugin package, so the
packaged pair is the default and both halves are built from source together.

If both artifacts are found, `validate_qemu_artifacts` checks them before any
run:

1. Both are readable files.
2. QEMU is a 64-bit little-endian ELF executable or shared object with an
   execute bit, and `--version` succeeds with a cleared environment.
3. The plugin is an ELF shared object exporting the defined global dynamic
   symbols `qemu_plugin_install` and `qemu_plugin_version`.
4. The QEMU build marker, `share/aos/crucible/qemu-build-identity.env` above
   `bin/` (or `qemu-build-identity.env` beside the binary), is a `key=value`
   file with `qemu_sim_capability=qemu-crucible`,
   `qemu_crucible_atomic_patch_applied=true`, `qemu_plugins_enabled=true`, and
   non-empty `qemu_build_id`, `qemu_atomic_patch_hash`,
   `qemu_shmem_abi_version`, `qemu_shmem_abi`, `qemu_shmem_header`, and
   `qemu_shmem_header_hash`.
5. The plugin marker, `nix-support/crucible-qemu-plugin-build-info` above
   `lib/` (or `crucible-qemu-plugin-build-info` beside the library), has
   non-empty `plugin_abi`, `qemu_build_id`, `shmem_abi_version`, `shmem_abi`,
   and `shmem_generated_header_hash`.
6. Cross-checks: the plugin ABI equals the ABI this CLI requires
   (`crucible-shmem-abi-v` followed by the engine's `SHMEM_ABI_VERSION`); the
   plugin was built for the QEMU's `qemu_build_id`; both advertise the same shmem
   ABI label, ABI version, and generated-header hash; each marker's ABI label
   matches its own version.

Every failure is a `CliError::Backend` (exit status 4) whose message names the
artifact, the mismatch, and the full discovery order. The resolved identity
(build id, atomic patch hash, plugin ABI, shmem ABI version) is carried in the
backend plan and written into reproduction artifacts (`CliIdentity` in
`.../cli/artifact.rs`, together with the engine version and ABIs, the
guest-host protocol version, and the RPC ABI version and build), so replay with
a different binary fails instead of reproducing something else.

## Seed resolution and determinism ergonomics

`plan_determinism_ergonomics` applies to commands that start a fresh run
identity (`run`, `verify` without `--compare`, `save`, `search`, `fuzz`).
`resume` and `replay` take their seed from the artifact or savepoint, and the
remaining commands need none (`seed_resolution_mode`).

`resolve_seed` uses `--seed`, else `CRUCIBLE_SEED`, else a generated seed drawn
once from `/dev/urandom` before the run. Supplied seeds parse as a decimal `u64`
or `0x`/`0X` hexadecimal (`parse_seed_value`). The resolved seed is announced at
run start as `0x%016x`, with its source, for example
`crucible: seed not set; generated seed = 0x... (set CRUCIBLE_SEED to pin)`.
Host entropy only chooses the run's identity; it is pinned into the request
(`pin_run_invocation_seed`) and never feeds execution.

`execute_determinism_ergonomics_plan` also checks, on every such invocation,
that all canonical trace renderers produce the same entry stream, that every
non-passing status produces an artifact, and that `canonical_state_wall_clock_guard`
holds: the CLI planning, routing, workflow, and reporting sources (embedded with
`include_str!`), plus the engine model and session crate roots, contain no
`SystemTime`, `Instant::now`, `std::time::Instant`, or `UNIX_EPOCH`. Wall-clock
time can therefore appear only in render-only output.

## Output and machine-readable mode

`--format` defaults to `table` when stdout is a terminal and `jsonl` otherwise
(`resolve_output_format`). `jsonl` and `json` are the machine formats
(`OutputFormat::is_machine_readable`).

- Canonical traces are rendered by `emit_canonical_trace` from
  `CanonicalLogEntry { sequence, virtual_time_ticks, node, kind, summary }`.
  `jsonl` streams one entry per line; `json` and `table` render the whole list.
  All three render the same entries; `--format` changes presentation only.
- `markdown` is reserved for triage reports. Commands that emit a canonical
  trace reject it as a usage error (`validate_canonical_trace_format`).
- `--trace <path>` also writes the JSONL stream to a file; `-q` suppresses the
  stdout copy.
- Human announcements (seed, backend) are printed only when not quiet and the
  format is not machine readable, so machine stdout is pure JSON or JSONL.
- Traces end with a `final_outcome` entry from node `cli` whose summary records
  the subcommand, status, exit code, canonical log digest, and artifact, so a
  consumer gets the verdict from the stream itself.

## Exit status

`CliError::exit_code` (`.../cli/report/error.rs`) is the single mapping; the
outcome codes come from `BackendCommandStatus`:

| Source | Code |
|--------|------|
| `Outcome(Passed)`, help, version | 0 |
| `Outcome(Failed)`, `ReplayCheck`, `Triage`, selftest failure | 1 |
| `Outcome(Timeout)` | 2 |
| `Outcome(Crashed)`, `Serve`, `Identity` | 3 |
| `Backend` (discovery, configuration, route, capability) | 4 |
| `Io`, `Store`, `Artifact`, `InvalidScenario` | 5 |
| `Usage`, including Clap parse errors | 64 |

`SaveWorkflowTrace` wraps another error with a failure trace and keeps its
source's code. Non-passing outcomes (`Failed`, `Crashed`, `Timeout`) are the
statuses that write a reproduction artifact and print the replay footer. The
user-facing status classes are listed in the
[reference](../../users/crucible/reference.md#output-artifacts-and-exit-status).

## `serve`

`run_serve_invocation` (`.../cli/verify_serve/service.rs`) hosts the control
API daemon:

1. `validate_serve_invocation` rejects `--max-sessions 0`, a zero or
   non-production `--qemu-rendezvous-ticks` or `--qemu-quantum-budget`, partial
   campaign flag groups, a partial `--tls-cert`/`--tls-key`/`--client-ca`
   triple, TLS combined with `--trusted-unauthenticated-bind`, and neither TLS
   nor explicit cleartext trust.
2. It builds a multi-threaded Tokio runtime and installs the shutdown signal
   (SIGINT or SIGTERM on Unix) before binding, so a client may stop the daemon as
   soon as it is reachable.
3. It binds the listener and prints
   `crucible: serving API daemon at <scheme>://<address> mode=<read-only|read-write>`
   unless `-q`.
4. Without `--production-qemu`, it serves a `LifecycleControlPlane` named
   `crucible-cli-daemon` whose sessions run `QuiescentLifecycleLoop`. With
   `--production-qemu`, it resolves the hermetic QEMU backend and serves
   `crucible-cli-qemu-daemon`, whose generic session factory refuses direct
   creation (nodes are created only through guarded campaign attempts) and which
   accepts authenticated campaign resumes. Both validate resume replay closures,
   apply `--max-sessions` with `with_max_sessions`, and select
   `LifecycleServerMode::read_only()` for `--read-only`.
5. It races the server against the shutdown signal. On a signal it triggers
   graceful server shutdown, waits up to `SERVE_SHUTDOWN_DRAIN_TIMEOUT` (1 s) for
   the server to drain, and returns success.

Serve-time bind and runtime errors are `CliError::Serve` (exit 3). The server's
multi-client, session-cap, read-only, and shutdown semantics are described in
[control-api.md](control-api.md#serving); campaign service attachments are
covered with campaigns.

## Help text and completions

Clap doc comments are user-facing `--help` text, not internal rustdoc. The
derive containers (`Cli`, `Commands`) carry no `///` overview prose; `Cli` sets
`about` in its `#[command]` attribute and disables the `help` subcommand. Each
flag and subcommand doc is short, imperative copy, and changing one is a CLI
change. Module overviews live in `//!` headers.

`crucible completions <SHELL>` takes a `clap_complete::Shell` value and
`write_completions` generates the script from the same `Cli::command()` used for
parsing, so completions and help cannot drift from the parser.
`crates/crucible/crucible-cli/tests/help_surface.rs` process-tests top-level and
subcommand help, long and short version output, and completions for Bash,
Elvish, Fish, PowerShell, and Zsh.

## Tests

| Check or target | Guards |
|-----------------|--------|
| `checks.crucible.phase5.cliSkeleton`, `cliThinWrapper` | Command surface and the thin-wrapper plan |
| `checks.crucible.phase5.cliBackendSelection` | Local/remote routing and route consistency |
| `checks.crucible.phase5.cliHermeticDiscovery` | Discovery order and marker validation |
| `checks.crucible.phase5.cliDeterminismErgonomics` | Seed resolution, trace formats, wall-clock guard |
| `checks.crucible.phase5.cliRunWorkflow`, `cliSaveWorkflow`, `cliResumeWorkflow`, `cliVerifyWorkflow`, `cliReplayCheck`, `cliSearchFuzzWorkflow`, `cliTriageWorkflow`, `cliSelftest` | Per-command workflows |
| `checks.crucible.phase5.cliServeReadOnly`, `cliServeMaxSessions`, `cliServeMultiClient`, `cliServeShutdown` | `serve` behavior |
| `checks.crucible.phase5.cliExitMachineReadable`, `cliCompletionsHelp` | Exit codes, pure machine stdout, help and completions |
| `crates/crucible/crucible-cli/tests/machine_readable.rs`, `serve_process.rs`, `help_surface.rs` | Process-level checks of the real binary |
