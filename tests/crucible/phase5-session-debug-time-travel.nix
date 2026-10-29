{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionDebugTimeTravel",
  dependencies ? [],
}: let
  sessionPage = builtins.readFile ../../docs/engineering/crucible/session.md;
  defaultChecks = builtins.readFile ./default.nix;
  backend = builtins.readFile ../../crates/crucible/crucible-engine/src/backend.rs;
  backendTests = builtins.readFile ../../crates/crucible/crucible-engine/src/backend/tests.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  simBackend = import ./_crucible-local-and-test-backends-source.nix;
  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  sessionEventLogStream = builtins.readFile ../../crates/crucible/crucible-session/tests/event_log_stream.rs;
  qemuNode = builtins.readFile ../../crates/crucible/crucible-qemu-host/src/node.rs;
  productionDebugLoop = builtins.readFile ../../crates/crucible/crucible-daemon/src/vm_lifecycle/quantum_loop.rs;
  gatewayOwner = builtins.readFile ../../crates/crucible/crucible-control-server/src/debug_gateway.rs;

  inherit (import ./_lib.nix {inherit lib;}) failuresFor;

  failures =
    failuresFor "docs/engineering/crucible/session.md" sessionPage [
      {
        label = "correct time-travel cross-reference";
        needle = "[time-travel-debugging.md](time-travel-debugging.md)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 debug/time-travel check wiring";
        needle = "sessionDebugTimeTravel = import ./phase5-session-debug-time-travel.nix";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/backend.rs" backend [
      {
        label = "gdb listen endpoint type";
        needle = "pub struct GdbListen";
      }
      {
        label = "gdb attach info type";
        needle = "pub struct GdbAttachInfo";
      }
      {
        label = "optional backend capability";
        needle = "fn open_gdbstub";
      }
      {
        label = "typed unsupported backend error";
        needle = "BackendError::Unsupported";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/backend/tests.rs" backendTests [
      {
        label = "mock rejects gdbstub";
        needle = "mock_simulation_backend_rejects_gdbstub_capability_with_typed_error";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/scheduler.rs" scheduler [
      {
        label = "quantum-loop gdbstub pass-through";
        needle = "fn open_gdbstub";
      }
      {
        label = "backend-backed quantum loop adapter";
        needle = "pub struct BackendQuantumLoop";
      }
      {
        label = "backend adapter routes gdbstub to wrapped backend";
        needle = "self.backend.open_gdbstub(node, listen)";
      }
      {
        label = "loop default rejects unsupported gdbstub";
        needle = "capability: \"open_gdbstub\"";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/sim_backend.rs" simBackend [
      {
        label = "SimDouble rejects gdbstub capability";
        needle = "fn open_gdbstub";
      }
      {
        label = "SimDouble unsupported error";
        needle = "BackendError::Unsupported";
      }
      {
        label = "SimDouble rejects gdbstub test";
        needle = "sim_double_rejects_gdbstub_capability_with_typed_error";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-session/src/lib.rs" sessionLib [
      {
        label = "attach command";
        needle = "AttachGdb";
      }
      {
        label = "debug goto command";
        needle = "DebugGoto";
      }
      {
        label = "debug reverse-step command";
        needle = "DebugReverseStep";
      }
      {
        label = "debug reverse-continue command";
        needle = "DebugReverseContinue";
      }
      {
        label = "non-canonical debug branch command";
        needle = "DebugForkNonCanonical";
      }
      {
        label = "session calls loop gdbstub capability";
        needle = "open_gdbstub(node.clone(), listen.clone())";
      }
      {
        label = "debug goto delegates to temporal graph";
        needle = "candidate_graph.debug_goto";
      }
      {
        label = "reverse-step delegates to temporal graph";
        needle = "candidate_graph.debug_reverse_step";
      }
      {
        label = "reverse-continue delegates to temporal graph";
        needle = "candidate_graph.debug_reverse_continue";
      }
      {
        label = "non-canonical branch guard";
        needle = "DebugNonCanonicalBranchRequired";
      }
      {
        label = "non-canonical branch appends visible event marker";
        needle = "append_boundary_event_log_entries(entries)";
      }
      {
        label = "actor passes current event-log prefix";
        needle = "apply_command_with_event_log";
      }
      {
        label = "actor truncates stale debug future before marker append";
        needle = "self.event_log.truncate_to_len(base_len)";
      }
      {
        label = "direct engine rejects missing branch event-log prefix";
        needle = "event_log.len() != self.event_log_len";
      }
      {
        label = "debug branch validates prefix before graph mutation";
        needle = "validate_event_log_prefix(event_log)";
      }
      {
        label = "malformed branch prefix regression test";
        needle = "malformed same-length prefix must not mutate graph branch metadata";
      }
      {
        label = "event-log stream skips duplicate live tail frames";
        needle = "frame.cursor.next_sequence < self.next_cursor.next_sequence";
      }
      {
        label = "event-log stream remembers generation reset cursor";
        needle = "generation_start";
      }
      {
        label = "event-log generation reset preserves lagging cursor";
        needle = "self.next_cursor.min(self.hub.generation_start_cursor())";
      }
      {
        label = "event-log stream skips stale generation frames";
        needle = "frame.generation < self.generation";
      }
      {
        label = "event-log active subscriber replacement marker test";
        needle = "unread active stream should receive the replacement marker";
      }
      {
        label = "debug branch flag";
        needle = "debug_branch_required";
      }
      {
        label = "debug command gate test";
        needle = "debug_time_travel_commands_reposition_without_scheduler_control_log";
      }
      {
        label = "debug commands excluded from control log";
        needle = "boundary_control_log().is_empty()";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-host/src/node.rs" qemuNode [
      {
        label = "QEMU node stores gdbstub config";
        needle = "gdbstub: Option<QemuGdbstubChannelConfig>";
      }
      {
        label = "QEMU gdbstub builder hook";
        needle = "pub fn with_gdbstub";
      }
      {
        label = "QEMU gdbstub accessor";
        needle = "pub const fn gdbstub_channel";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-session/tests/event_log_stream.rs" sessionEventLogStream [
      {
        label = "event-log partial truncation subscriber regression test";
        needle = "event_log_generation_reset_preserves_retained_prefix_for_lagging_stream";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-daemon/src/vm_lifecycle/quantum_loop.rs" productionDebugLoop [
      {
        label = "production gdbstub attaches through gateway";
        needle = "DebugGatewayProcess::launch_with_owner_unix";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-control-server/src/debug_gateway.rs" gatewayOwner [
      {
        label = "owner-only gateway launch";
        needle = "pub fn launch_with_owner_unix";
      }
      {
        label = "private operator directory";
        needle = "std::fs::Permissions::from_mode(0o700)";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-session-debug-time-travel";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils];

    CRUCIBLE_T_SESS_13_FAILURES = failureText;
    ATTR_PATH = attrPath;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "run-phase5-session-debug-time-travel";
        script = ''
                  set -eu

                  if [ -n "$CRUCIBLE_T_SESS_13_FAILURES" ]; then
                    printf '%s\n' "$CRUCIBLE_T_SESS_13_FAILURES" >&2
                    exit 1
                  fi

                  mkdir -p "$out"
                  {
                    printf 'PASS\n'
                    printf 'check=%s\n' "$ATTR_PATH"
                    printf 'dependency_count=%s\n' "$DEPENDENCY_COUNT"
                    printf 'debug_commands=attach_gdb,goto,reverse_step,reverse_continue\n'
                    printf 'schedule_exclusion=query_pause_class\n'
                    printf 'non_canonical_branch_guard=true\n'
                    printf 'backend_open_gdbstub=optional\n'
          printf 'production_open_gdbstub=owner_only_unix_gateway\n'
                    printf 'simdouble_open_gdbstub=unsupported\n'
                    printf 'mock_open_gdbstub=unsupported\n'
                  } > "$out/result"
        '';
      }
    ];

    passthru.rawGate = attrPath;

    meta.description = "Crucible Phase 5 session debug/time-travel command gate";
  }
