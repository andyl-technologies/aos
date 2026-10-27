{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionCommandSet",
  taskIds ? ["T-SESS-4"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-4 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionCommandSet`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 command set status note";
        needle = "`T-SESS-4` is green through `checks.crucible.phase5.sessionCommandSet`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-session/src/lib.rs" sessionLib [
      {
        label = "reply wrapper";
        needle = "pub struct CommandReply<T>";
      }
      {
        label = "oneshot reply result";
        needle = "oneshot::Sender<Result<T, SessionError>>";
      }
      {
        label = "breakpoint command payload";
        needle = "pub struct BreakpointSpec";
      }
      {
        label = "breakpoint policy taxonomy";
        needle = "pub enum BreakpointPolicy";
      }
      {
        label = "breakpoint disposition taxonomy";
        needle = "pub enum BreakpointDisposition";
      }
      {
        label = "fork source taxonomy";
        needle = "pub enum CheckpointRef";
      }
      {
        label = "fork reply handle";
        needle = "pub struct SessionHandle";
      }
      {
        label = "savepoint reply payload";
        needle = "pub struct SavepointInfo";
      }
      {
        label = "query taxonomy";
        needle = "pub enum QueryKind";
      }
      {
        label = "query reply payload";
        needle = "pub enum QueryResult";
      }
      {
        label = "set-breakpoint command";
        needle = "SetBreakpoint {";
      }
      {
        label = "remove-breakpoint command";
        needle = "RemoveBreakpoint {";
      }
      {
        label = "create-savepoint command";
        needle = "CreateSavepoint {";
      }
      {
        label = "fork command";
        needle = "Fork {";
      }
      {
        label = "query command";
        needle = "Query {";
      }
      {
        label = "reply-bearing command fields";
        needle = "reply: CommandReply";
      }
      {
        label = "fork checkpoint resolver";
        needle = "fn resolve_fork_checkpoint";
      }
      {
        label = "graph-backed savepoint";
        needle = "self.graph.save_checkpoint(&self.configuration)";
      }
      {
        label = "breakpoint insert mapping";
        needle = "self.breakpoints.insert(spec.clone())";
      }
      {
        label = "breakpoint remove mapping";
        needle = "self.breakpoints.remove(*id)";
      }
      {
        label = "successful reply completion";
        needle = "reply.complete(Ok(";
      }
      {
        label = "actor rejected reply completion";
        needle = "command.complete_error(error.clone())";
      }
      {
        label = "terminal accepted drain";
        needle = "command.is_terminal_accepted()";
      }
      {
        label = "terminal rejected reply completion";
        needle = "self.engine.invalid_transition(command.clone())";
      }
      {
        label = "reply payload success test";
        needle = "rfc_command_payloads_return_replies_through_engine_boundary";
      }
      {
        label = "reply rejection test";
        needle = "rfc_command_rejections_complete_reply_oneshots_without_side_effects";
      }
      {
        label = "terminal drain reply test";
        needle = "rfc_command_terminal_drain_completes_queued_replies";
      }
      {
        label = "running local acknowledgement test";
        needle = "rfc_command_running_actor_acknowledges_local_boundary_replies_immediately";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session command-set check";
        needle = "sessionCommandSet = import ./phase5-session-command-set.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session-command-set check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase5-session-command-set";

      runtimeDeps = [pkgs.sqlite];

      buildDeps =
        [
          pkgs.sqlite
          pkgs.coreutils
          pkgs.sed
        ]
        ++ dependencies;

      phases = [
        {
          name = "run-session-command-set";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-session \
              --lib \
              rfc_command \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            component=crucible-session
            command_set=closed-rfc-section-4
            replies=oneshot
            graph_mapping=savepoint-and-fork
            scheduler_mapping=fault-and-query-control
            RESULT
          '';
        }
      ];
    }
