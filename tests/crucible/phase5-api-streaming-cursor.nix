{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiStreamingCursor",
  taskIds ? ["T-API-6"],
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
  eventLogStream = builtins.readFile ../../crates/crucible-api/src/event_log_stream.rs;
  streaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  client = builtins.readFile ../../crates/crucible-api/src/client.rs;
  session = import ./_crucible-session-source.nix {inherit lib;};
  streamingCursorTest = builtins.readFile ../../crates/crucible-api/tests/gate_streaming_cursor.rs;
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
        label = "T-API-6 checked off";
        needle = "- [x] **T-API-6**";
      }
      {
        label = "T-API-6 completion note";
        needle = "Completed by `checks.crucible.phase5.apiStreamingCursor`";
      }
      {
        label = "T-API-7 completion note";
        needle = "Completed by `checks.crucible.phase5.apiStateUpdateStream`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API streaming cursor status note";
        needle = "`T-API-6` is green through `checks.crucible.phase5.apiStreamingCursor`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "attach snapshot re-exported";
        needle = "AttachSnapshot";
      }
      {
        label = "streaming event frame re-exported";
        needle = "StreamingEventFrame";
      }
      {
        label = "session event-log snapshot re-exported";
        needle = "SessionEventLogSnapshot";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/event_log_stream.rs" eventLogStream [
      {
        label = "attach-tail subscription";
        needle = "subscribe_with_replay_tail";
      }
      {
        label = "log-derived snapshot facade";
        needle = "snapshot_through";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/streaming.rs" streaming [
      {
        label = "snapshot-on-attach capability";
        needle = "snapshot_on_attach";
      }
      {
        label = "attach snapshot type";
        needle = "pub struct AttachSnapshot";
      }
      {
        label = "API event frame type";
        needle = "pub struct StreamingEventFrame";
      }
      {
        label = "event envelope conversion";
        needle = "open_set_event_envelope_from_entry";
      }
      {
        label = "control/watch event receive helper";
        needle = "recv_event";
      }
      {
        label = "lagged event stream error";
        needle = "EventStreamLagged";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" client [
      {
        label = "ControlClient attach returns a stream handle";
        needle = "ClientControlStream";
      }
      {
        label = "Watch attach returns a stream handle";
        needle = "ClientWatchStream";
      }
      {
        label = "RPC framed event decoder";
        needle = "decode_streaming_event_frame";
      }
      {
        label = "RPC streaming frame reader";
        needle = "read_next_framed_rpc_message";
      }
      {
        label = "RPC attached snapshot decoding";
        needle = "parse_attach_snapshot_line";
      }
      {
        label = "RPC snapshot line prefix";
        needle = ''"snapshot="'';
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "session event-log snapshot";
        needle = "pub struct SessionEventLogSnapshot";
      }
      {
        label = "session attach-tail subscription";
        needle = "subscribe_with_replay_tail";
      }
      {
        label = "session snapshot fold";
        needle = "snapshot_through";
      }
      {
        label = "debug append helper";
        needle = "append_event_log_entries_for_test";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_streaming_cursor.rs" streamingCursorTest [
      {
        label = "replay/live-tail test";
        needle = "streaming_cursor_replays_then_live_tails_api_events";
      }
      {
        label = "observational flag coverage";
        needle = "observational.event.observational";
      }
      {
        label = "snapshot coverage";
        needle = "snapshot_on_attach";
      }
      {
        label = "attach beyond tail coverage";
        needle = "attach beyond current length should skip historical replay";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" controlClientTest [
      {
        label = "RPC Control event receive coverage";
        needle = "recv_rpc_control_event";
      }
      {
        label = "RPC Watch event receive coverage";
        needle = "recv_rpc_watch_event";
      }
      {
        label = "HTTP/2 streaming response body";
        needle = "http2_stream_response";
      }
      {
        label = "RPC live-tail coverage";
        needle = "control_live_start";
      }
      {
        label = "RPC event-frame encoder in gate";
        needle = "encode_streaming_event_frame";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API streaming cursor check";
        needle = "apiStreamingCursor = import ./phase5-api-streaming-cursor.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-streaming-cursor";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_6_FAILURES = failureText;
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
        name = "run-phase5-api-streaming-cursor";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_6_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_6_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-streaming-cursor-target" \
            -p crucible-api \
            --test gate_streaming_cursor \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 API streaming cursor gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }
