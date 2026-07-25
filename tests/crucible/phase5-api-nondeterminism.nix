{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiNondeterminism",
  taskIds ? ["T-API-14"],
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
  client = builtins.readFile ../../crates/crucible-api/src/client.rs;
  lifecycle = builtins.readFile ../../crates/crucible-api/src/lifecycle.rs;
  sessionMapping = builtins.readFile ../../crates/crucible-api/src/session_mapping.rs;
  streaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  controlClientTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_client.rs;
  reproductionTest = builtins.readFile ../../crates/crucible-api/tests/gate_reproduction_context.rs;
  streamingCursorTest = builtins.readFile ../../crates/crucible-api/tests/gate_streaming_cursor.rs;
  defaultChecks = builtins.readFile ./default.nix;

  apiSources = client + lifecycle + sessionMapping + streaming;
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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-14 checked off";
        needle = "- [x] **T-API-14**";
      }
      {
        label = "T-API-14 completion note";
        needle = "Completed by `checks.crucible.phase5.apiNondeterminism`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API nondeterminism status note";
        needle = "`T-API-14` is green through";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" controlClientTest [
      {
        label = "API nondeterminism gate test";
        needle = "api_nondeterminism_gate_proves_transport_observers_wall_clock_and_read_only_traffic_do_not_perturb_state";
      }
      {
        label = "transport-agnostic nondeterminism driver";
        needle = "drive_api_nondeterminism_projection";
      }
      {
        label = "quiet traffic profile";
        needle = "ApiDeterminismTraffic::Quiet";
      }
      {
        label = "noisy traffic profile";
        needle = "ApiDeterminismTraffic::Noisy";
      }
      {
        label = "quiet RPC lane";
        needle = "quiet_rpc.normalized()";
      }
      {
        label = "server-observed RPC read/mutate arrival lane";
        needle = "drive_rpc_arrival_permutation_projection";
      }
      {
        label = "server-observed RPC arrival log";
        needle = "take_arrivals";
      }
      {
        label = "read-before-mutate observed order";
        needle = ''vec!["get-reproduction", "send"]'';
      }
      {
        label = "mutate-before-read observed order";
        needle = ''vec!["send", "get-reproduction"]'';
      }
      {
        label = "concurrent RPC join";
        needle = "tokio::join!";
      }
      {
        label = "observer load control streams";
        needle = "observer_controls";
      }
      {
        label = "observer load watch streams";
        needle = "observer_watches";
      }
      {
        label = "wall-clock gap simulation stays outside scheduler input";
        needle = "simulate_wall_clock_gap_without_scheduler_input";
      }
      {
        label = "read-only traffic neutrality assertion";
        needle = "assert_read_only_traffic_is_schedule_neutral";
      }
      {
        label = "Hello read-only traffic";
        needle = "Hello should succeed";
      }
      {
        label = "ListScenarios read-only traffic";
        needle = "ListScenarios should succeed";
      }
      {
        label = "query-class read-only command";
        needle = "SessionCommand::query_snapshot()";
      }
      {
        label = "event-log cursor projection";
        needle = "final_event_count";
      }
      {
        label = "causal event count projection";
        needle = "causal_event_count";
      }
      {
        label = "observational event count projection";
        needle = "observational_event_count";
      }
      {
        label = "last event sequence projection";
        needle = "last_sequence";
      }
      {
        label = "streaming causal projection lane";
        needle = "drive_streaming_causal_subsequence_projection";
      }
      {
        label = "causal event replay capture";
        needle = "capture_streaming_causal_projection";
      }
      {
        label = "non-vacuous causal event payload projection";
        needle = "causal_events";
      }
      {
        label = "observer pressure event burst";
        needle = "event_burst(0, 7_000, 8)";
      }
      {
        label = "in-process noisy equivalence assertion";
        needle = "baseline.normalized(),\n        noisy_in_process.normalized()";
      }
      {
        label = "quiet RPC equivalence assertion";
        needle = "baseline.normalized(),\n        quiet_rpc.normalized()";
      }
      {
        label = "RPC noisy equivalence assertion";
        needle = "baseline.normalized(),\n        noisy_rpc.normalized()";
      }
      {
        label = "arrival-order RPC equivalence assertion";
        needle = "baseline.normalized(),\n        arrival_rpc.normalized()";
      }
      {
        label = "causal projection equivalence assertion";
        needle = "quiet_causal, noisy_causal";
      }
      {
        label = "HTTP/2 transport proof";
        needle = "ControlTransportKind::Http2Rpc";
      }
      {
        label = "boundary-mutating injected fault";
        needle = "SessionCommandKind::InjectFault";
      }
      {
        label = "boundary-mutating healed fault";
        needle = "SessionCommandKind::HealFault";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_reproduction_context.rs" reproductionTest [
      {
        label = "GetReproduction read-only proof";
        needle = "GetReproduction must not append or truncate the event-log stream";
      }
      {
        label = "query-class reproduction exclusion";
        needle = "GetReproduction should read context";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_streaming_cursor.rs" streamingCursorTest [
      {
        label = "streaming attach pure observation proof";
        needle = "attach beyond current length should skip historical replay";
      }
      {
        label = "watch does not mutate state";
        needle = "fixture.live.read().state_kind, before_state";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/session_mapping.rs" sessionMapping [
      {
        label = "server observation read-only dispatch";
        needle = "Self::ServerObservation | Self::ReproductionLogRead => true";
      }
      {
        label = "live mirror read-only dispatch";
        needle = "Self::LiveMirrorRead { .. } | Self::WatchStream { .. } => true";
      }
      {
        label = "reproduction log read dispatch";
        needle = "ApiDispatch::ReproductionLogRead";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API nondeterminism check";
        needle = "apiNondeterminism = import ./phase5-api-nondeterminism.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible-api/src" apiSources [
      {
        label = "wall-clock Instant dependency";
        needle = "Instant::now";
      }
      {
        label = "wall-clock SystemTime dependency";
        needle = "SystemTime::now";
      }
      {
        label = "std Instant import";
        needle = "std::time::Instant";
      }
      {
        label = "std SystemTime import";
        needle = "std::time::SystemTime";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-nondeterminism";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_14_FAILURES = failureText;
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
        name = "run-phase5-api-nondeterminism";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_14_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_14_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-nondeterminism-target" \
            -p crucible-api \
            --test gate_control_client \
            api_nondeterminism_gate_proves_transport_observers_wall_clock_and_read_only_traffic_do_not_perturb_state \
            -- --exact --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-nondeterminism-target" \
            -p crucible-api \
            --test gate_reproduction_context \
            reproduction_context_is_read_only_and_visible_on_attach_snapshot \
            -- --exact --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-nondeterminism-target" \
            -p crucible-api \
            --test gate_streaming_cursor \
            streaming_cursor_replays_then_live_tails_api_events \
            -- --exact --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 API nondeterminism gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }
