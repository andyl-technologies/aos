{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiStreamingEquivalence",
  taskIds ? ["T-API-4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiClient = builtins.readFile ../../crates/crucible-api/src/client.rs;
  streaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  streamingTest = builtins.readFile ../../crates/crucible-api/tests/gate_streaming_equivalence.rs;
  controlClientTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_client.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-4 completion note";
        needle = "Completed by `checks.crucible.phase5.apiStreamingEquivalence`";
      }
      {
        label = "T-API-5 completion note";
        needle = "Completed by `checks.crucible.phase5.apiOpenSetPayload`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API streaming status note";
        needle = "`T-API-4` is green through `checks.crucible.phase5.apiStreamingEquivalence`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "streaming module exported";
        needle = "pub mod streaming";
      }
      {
        label = "in-process streaming session re-exported";
        needle = "InProcessStreamingSession";
      }
      {
        label = "streaming equivalence validator re-exported";
        needle = "validate_control_watch_send_equivalence";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" apiClient [
      {
        label = "Control attach client method";
        needle = "fn control_attach(";
      }
      {
        label = "Control send client method";
        needle = "fn control_send(";
      }
      {
        label = "Watch attach client method";
        needle = "fn watch_attach(";
      }
      {
        label = "Send command client method";
        needle = "fn send_command(";
      }
      {
        label = "RPC Control attach path";
        needle = ''"/crucible.rpc/control/attach"'';
      }
      {
        label = "RPC Control send path";
        needle = ''"/crucible.rpc/control/send"'';
      }
      {
        label = "RPC Watch path";
        needle = ''"/crucible.rpc/watch"'';
      }
      {
        label = "RPC Send path";
        needle = ''"/crucible.rpc/send"'';
      }
    ]
    ++ failuresFor "crates/crucible-api/src/streaming.rs" streaming [
      {
        label = "streaming session facade";
        needle = "pub struct InProcessStreamingSession";
      }
      {
        label = "control stream handle";
        needle = "pub struct ControlStream";
      }
      {
        label = "watch stream handle";
        needle = "pub struct WatchStream";
      }
      {
        label = "send request";
        needle = "pub struct SendRequest";
      }
      {
        label = "send response";
        needle = "pub struct SendResponse";
      }
      {
        label = "state update";
        needle = "pub struct StateUpdate";
      }
      {
        label = "shared command capabilities";
        needle = "StreamingCapabilitySet::current";
      }
      {
        label = "control send equivalence validator";
        needle = "pub fn validate_control_watch_send_equivalence";
      }
      {
        label = "full session command coverage";
        needle = "SessionCommandKind::ALL";
      }
      {
        label = "one command per envelope";
        needle = "CommandDispatchCardinality::OneSessionCommandPerEnvelope";
      }
      {
        label = "session transition model reused";
        needle = "lifecycle_transition";
      }
      {
        label = "typed command result";
        needle = "pub struct CommandResult";
      }
      {
        label = "invalid-state command result";
        needle = "CommandRejectionKind::InvalidState";
      }
      {
        label = "watch subscribes to event log";
        needle = "event_log.subscribe";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_streaming_equivalence.rs" streamingTest [
      {
        label = "capability equivalence test";
        needle = "control_and_watch_send_advertise_identical_command_capabilities";
      }
      {
        label = "lifecycle drive equivalence test";
        needle = "control_stream_and_watch_send_drive_the_same_session_lifecycle";
      }
      {
        label = "non-basic command drive test";
        needle = "control_and_send_drive_non_basic_command_classes";
      }
      {
        label = "invalid command equivalence test";
        needle = "control_and_send_reject_invalid_lifecycle_commands_equivalently";
      }
      {
        label = "state update assertion";
        needle = "Some(LiveStateKind::Paused)";
      }
      {
        label = "send response assertion";
        needle = "SendRequest::new";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" controlClientTest [
      {
        label = "RPC Control attach coverage";
        needle = "RPC Control attach should decode";
      }
      {
        label = "RPC Control send coverage";
        needle = "RPC Control send should decode";
      }
      {
        label = "RPC Watch attach coverage";
        needle = "RPC Watch attach should decode";
      }
      {
        label = "RPC Send coverage";
        needle = "RPC Send should decode";
      }
      {
        label = "RPC Send Stop cleanup coverage";
        needle = "RPC Send Stop should decode";
      }
      {
        label = "destroy idempotent after streaming stop";
        needle = "RPC destroy after streaming Stop should decode";
      }
      {
        label = "RPC streaming rejection coverage";
        needle = "RPC Send rejection should decode";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API streaming equivalence check";
        needle = "apiStreamingEquivalence = import ./phase5-api-streaming-equivalence.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-streaming-equivalence";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_4_FAILURES = failureText;
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
        name = "run-phase5-api-streaming-equivalence";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_4_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_4_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-streaming-equivalence-target" \
            -p crucible-api \
            --test gate_streaming_equivalence \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-streaming-equivalence-target" \
            -p crucible-api \
            --test gate_control_client \
            -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          set -eu

          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'check=%s\n' "$ATTR_PATH"
            printf 'tasks=%s\n' "$TASK_IDS"
            printf 'dependency_count=%s\n' "$DEPENDENCY_COUNT"
            printf 'control=bidirectional_attach_and_command\n'
            printf 'watch=read_only_attach\n'
            printf 'send=unary_command_result\n'
            printf 'equivalence=shared_command_capabilities\n'
            printf 'rpc_streaming=control_watch_send_paths\n'
          } > "$out/result"
        '';
      }
    ];
  }
