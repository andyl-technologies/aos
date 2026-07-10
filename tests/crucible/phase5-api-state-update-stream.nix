{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiStateUpdateStream",
  taskIds ? ["T-API-7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  streaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  client = builtins.readFile ../../crates/crucible-api/src/client.rs;
  lifecycle = builtins.readFile ../../crates/crucible-api/src/lifecycle.rs;
  session = import ./_crucible-session-source.nix {inherit lib;};
  streamingEquivalenceTest = builtins.readFile ../../crates/crucible-api/tests/gate_streaming_equivalence.rs;
  controlClientTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_client.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-7 checked off";
        needle = "- [x] **T-API-7**";
      }
      {
        label = "T-API-7 completion note";
        needle = "Completed by `checks.crucible.phase5.apiStateUpdateStream`";
      }
      {
        label = "T-API-8 completion note";
        needle = "Completed by `checks.crucible.phase5.apiEpochGuards`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API state update status note";
        needle = "`T-API-7` is green through `checks.crucible.phase5.apiStateUpdateStream`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "streaming state update frame re-exported";
        needle = "StreamingStateUpdateFrame";
      }
      {
        label = "combined streaming frame re-exported";
        needle = "StreamingFrame";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/streaming.rs" streaming [
      {
        label = "state update frame type";
        needle = "pub struct StreamingStateUpdateFrame";
      }
      {
        label = "state update receive helper";
        needle = "recv_state_update";
      }
      {
        label = "combined stream frame helper";
        needle = "recv_frame";
      }
      {
        label = "state transition subscription";
        needle = "state_transitions.subscribe";
      }
      {
        label = "state update lag error";
        needle = "StateUpdateStreamLagged";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" client [
      {
        label = "RPC state update frame decoder";
        needle = "decode_streaming_state_update_frame";
      }
      {
        label = "RPC state update receive helper";
        needle = "recv_state_update";
      }
      {
        label = "RPC shared frame queue";
        needle = "frames: mpsc::Receiver<Result<RpcStreamingFrame";
      }
      {
        label = "RPC pending state update buffer";
        needle = "pending_state_updates";
      }
      {
        label = "RPC state update frame header";
        needle = "crucible.rpc/state-update-frame";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lifecycle.rs" lifecycle [
      {
        label = "lifecycle stores state transition bus";
        needle = "state_transitions";
      }
      {
        label = "lifecycle passes state transition bus to streaming session";
        needle = "runtime.state_transitions.clone";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "state transition bus";
        needle = "pub struct SessionStateTransitionBus";
      }
      {
        label = "state transition stream";
        needle = "pub struct SessionStateTransitionStream";
      }
      {
        label = "actor publishes state transitions";
        needle = "state_transitions.publish";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_streaming_equivalence.rs" streamingEquivalenceTest [
      {
        label = "Watch-only state update test";
        needle = "watch_only_state_updates_are_monotone_and_not_event_log_entries";
      }
      {
        label = "monotone sequence assertion";
        needle = "continued_update.sequence > last_sequence";
      }
      {
        label = "event-log separation assertion";
        needle = "StateUpdate delivery must remain distinct from event-log entries";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" controlClientTest [
      {
        label = "RPC Control state update coverage";
        needle = "recv_rpc_control_state_update";
      }
      {
        label = "RPC Watch state update coverage";
        needle = "recv_rpc_watch_state_update";
      }
      {
        label = "HTTP/2 state-update frame encoder";
        needle = "encode_streaming_state_update_frame";
      }
      {
        label = "RPC state update starvation regression";
        needle = "event_burst(watch_burst_start";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API state update stream check";
        needle = "apiStateUpdateStream = import ./phase5-api-state-update-stream.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-state-update-stream";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_7_FAILURES = failureText;
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
        name = "run-phase5-api-state-update-stream";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_7_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_7_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-state-update-stream-target" \
            -p crucible-api \
            --test gate_streaming_equivalence \
            watch_only_state_updates_are_monotone_and_not_event_log_entries \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 API state update stream gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }
