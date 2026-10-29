{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionCommandSet",
  taskIds ? ["T-SESS-4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/crucible-session/src/lib.rs" sessionLib [
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
        needle = "session_command_payloads_return_replies_through_engine_boundary";
      }
      {
        label = "reply rejection test";
        needle = "session_command_rejections_complete_reply_oneshots_without_side_effects";
      }
      {
        label = "terminal drain reply test";
        needle = "session_command_terminal_drain_completes_queued_replies";
      }
      {
        label = "running local acknowledgement test";
        needle = "session_command_running_actor_acknowledges_local_boundary_replies_immediately";
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
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-command-set";
      version = "0";
      src = crucibleSrc;

      runtimeDeps = [pkgs.sqlite];

      buildDeps =
        [
          pkgs.sqlite
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-session-command-set";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-command-set-target" \
              -p crucible-session \
              --lib \
              session_command_ \
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
            command_set=closed
            replies=oneshot
            graph_mapping=savepoint-and-fork
            scheduler_mapping=fault-and-query-control
            RESULT
          '';
        }
      ];
    }
