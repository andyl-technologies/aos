{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiCommandStatusTaxonomy",
  taskIds ? ["T-API-10"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  streaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  session = import ./_crucible-session-source.nix {inherit lib;};
  client = builtins.readFile ../../crates/crucible-api/src/client.rs;
  rpcAbi = builtins.readFile ../../crates/crucible-api/src/rpc_abi.rs;
  controlClientTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/tests/gate_control_client.rs;
  };
  abiTest = builtins.readFile ../../crates/crucible-api/tests/gate_abi_conformance.rs;
  streamingEquivalenceTest = builtins.readFile ../../crates/crucible-api/tests/gate_streaming_equivalence.rs;
  explorationForkTest = builtins.readFile ../../crates/crucible-session/tests/gate_exploration_fork.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-10 completion note";
        needle = "Completed by `checks.crucible.phase5.apiCommandStatusTaxonomy`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API command status status note";
        needle = "`T-API-10` is green through";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/streaming.rs" streaming [
      {
        label = "command rejection enum";
        needle = "pub enum CommandRejectionKind";
      }
      {
        label = "invalid state code";
        needle = "InvalidState";
      }
      {
        label = "not found code";
        needle = "NotFound";
      }
      {
        label = "invalid argument code";
        needle = "InvalidArgument";
      }
      {
        label = "unsupported code";
        needle = "Unsupported";
      }
      {
        label = "internal code";
        needle = "Internal";
      }
      {
        label = "command rejection to RPC status";
        needle = "pub const fn rpc_status";
      }
      {
        label = "RPC status to command rejection";
        needle = "impl TryFrom<RpcStatusCode> for CommandRejectionKind";
      }
      {
        label = "reply-bearing command observer";
        needle = "enum CommandReplyObserver";
      }
      {
        label = "commands rebuilt with observable replies";
        needle = "command_with_reply_observer";
      }
      {
        label = "commands wrapped with actor acknowledgement";
        needle = "SessionCommand::acknowledged(command,";
      }
      {
        label = "session errors mapped to command rejections";
        needle = "session_error_rejection_kind";
      }
      {
        label = "actor missing breakpoint maps to not found";
        needle = "SessionError::BreakpointNotFound { .. } => CommandRejectionKind::NotFound";
      }
      {
        label = "absent breakpoint removal maps to not found";
        needle = "Ok(false) => Some(CommandRejectionKind::NotFound)";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "actor recovers command-scope rejections";
        needle = "is_recoverable_command_rejection";
      }
      {
        label = "acknowledged command wrapper";
        needle = "SessionCommand::Acknowledge";
      }
      {
        label = "side-effect-free absent breakpoint error";
        needle = "BreakpointNotFound";
      }
      {
        label = "run loop uses recoverable command wrapper";
        needle = "apply_command_or_recover";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" client [
      {
        label = "typed RPC status client error";
        needle = "RpcStatus";
      }
      {
        label = "typed RPC status parser";
        needle = "parse_rpc_status_line";
      }
      {
        label = "closed command status parser";
        needle = "parse_command_status_line";
      }
      {
        label = "scenario not found decoder";
        needle = "decode_scenario_not_found";
      }
      {
        label = "lifecycle session not found decoder";
        needle = "decode_lifecycle_session_not_found";
      }
      {
        label = "streaming session not found decoder";
        needle = "decode_streaming_session_not_found";
      }
      {
        label = "success status forbidden in error envelope";
        needle = "RPC error response used success status";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/rpc_abi.rs" rpcAbi [
      {
        label = "status code enum";
        needle = "pub enum RpcStatusCode";
      }
      {
        label = "status wire formatter";
        needle = "rpc_status_code_wire_name";
      }
      {
        label = "status wire parser";
        needle = "rpc_status_code_from_wire_name";
      }
      {
        label = "RPC minor bumped";
        needle = "pub const RPC_PROTOCOL_MINOR: u16 = 0;";
      }
      {
        label = "rejected command golden vector";
        needle = "name: \"send-response-rejected-not-found\"";
      }
      {
        label = "typed error golden vector";
        needle = "name: \"rpc-error-invalid-state\"";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "RPC status parser re-export";
        needle = "rpc_status_code_from_wire_name";
      }
      {
        label = "RPC status formatter re-export";
        needle = "rpc_status_code_wire_name";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client*.rs" controlClientTest [
      {
        label = "closed taxonomy conversion coverage";
        needle = "assert_command_rejection_taxonomy_is_closed";
      }
      {
        label = "unknown scenario typed not found";
        needle = "RPC unknown scenario should decode as typed NOT_FOUND";
      }
      {
        label = "absent lifecycle session typed not found";
        needle = "RPC GetReproduction on absent session should decode as typed NOT_FOUND";
      }
      {
        label = "absent streaming session typed not found";
        needle = "RPC Watch on absent session should reject";
      }
      {
        label = "invalid argument transport status coverage";
        needle = "RpcStatusCode::InvalidArgument";
      }
      {
        label = "stream remains usable after rejected command";
        needle = "RPC Send Stop should decode";
      }
      {
        label = "real RPC send rejected response encoder";
        needle = "assert_raw_send_rejection";
      }
      {
        label = "real RPC send response rejected status";
        needle = "status=rejected:{expected_status}";
      }
      {
        label = "live five-code status taxonomy test";
        needle = "in_process_send_rejections_use_closed_status_taxonomy_without_closing_stream";
      }
      {
        label = "live backend invalid argument command status";
        needle = "in_process_send_maps_backend_rejections_to_invalid_argument";
      }
      {
        label = "live payload-free actor failure command status";
        needle = "in_process_send_observes_payload_free_actor_failures";
      }
      {
        label = "RPC send covers all rejection statuses";
        needle = "rpc_send_decodes_all_rejection_statuses_and_golden_error_bytes";
      }
      {
        label = "live invalid argument command status";
        needle = "CommandRejectionKind::InvalidArgument";
      }
      {
        label = "live internal command status";
        needle = "CommandRejectionKind::Internal";
      }
      {
        label = "malformed send request returns typed status";
        needle = "assert_raw_send_error";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_abi_conformance.rs" abiTest [
      {
        label = "rejected status vector assertion";
        needle = "send-response-rejected-not-found";
      }
      {
        label = "typed error vector assertion";
        needle = "rpc-error-invalid-state";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_streaming_equivalence.rs" streamingEquivalenceTest [
      {
        label = "streaming equivalence regression test";
        needle = "control_and_send_drive_non_basic_command_classes";
      }
      {
        label = "streaming equivalence observes typed not found";
        needle = "reason: CommandRejectionKind::NotFound";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_exploration_fork.rs" explorationForkTest [
      {
        label = "unwrapped actor missing checkpoint remains fatal";
        needle = "actor_fork_command_completes_reply_on_missing_checkpoint";
      }
      {
        label = "unwrapped actor task returns missing checkpoint error";
        needle = "Ok(Err(SessionError::Engine(crucible::EngineError::CheckpointNotRecorded";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API command status taxonomy check";
        needle = "apiCommandStatusTaxonomy = import ./phase5-api-command-status-taxonomy.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-command-status-taxonomy";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_10_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
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
        name = "run-phase5-api-command-status-taxonomy";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_10_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_10_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-command-status-taxonomy-target" \
            -p crucible-api \
            --test gate_control_client \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-command-status-taxonomy-target" \
            -p crucible-api \
            --test gate_abi_conformance \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-command-status-taxonomy-target" \
            -p crucible-api \
            --test gate_streaming_equivalence \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-command-status-taxonomy-target" \
            -p crucible-session \
            --test gate_exploration_fork \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 API command status taxonomy gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }
