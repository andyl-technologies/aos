{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogControlPlaneStreaming",
  taskIds ? ["T-OBS-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  session = builtins.readFile ../../crates/crucible-session/src/lib.rs;
  sessionGate = builtins.readFile ../../crates/crucible-session/tests/gate_control_responsive.rs;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiStream = builtins.readFile ../../crates/crucible-api/src/event_log_stream.rs;
  apiGate = builtins.readFile ../../crates/crucible-api/tests/gate_control_responsive.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

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

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-11 checked off";
        needle = "- [x] **T-OBS-11**";
      }
      {
        label = "T-OBS-11 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogControlPlaneStreaming`";
      }
      {
        label = "cursor and command-correlation completion note";
        needle = "including `Command`-sourced control correlations";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "event-log cursor type";
        needle = "pub struct EventLogCursor";
      }
      {
        label = "event-log stream frame type";
        needle = "pub struct SessionEventLogFrame";
      }
      {
        label = "event-log stream error type";
        needle = "pub enum SessionEventLogStreamError";
      }
      {
        label = "session event-log hub";
        needle = "pub struct SessionEventLog";
      }
      {
        label = "bounded broadcast tail";
        needle = "broadcast::channel(SESSION_EVENT_LOG_BROADCAST_CAPACITY)";
      }
      {
        label = "bounded retained replay batch";
        needle = "pub const SESSION_EVENT_LOG_REPLAY_BATCH_SIZE";
      }
      {
        label = "session current cursor API";
        needle = "pub fn current_cursor(&self) -> EventLogCursor";
      }
      {
        label = "cursor-backed subscribe API";
        needle = "pub fn subscribe(&self, cursor: EventLogCursor) -> SessionEventLogStream";
      }
      {
        label = "future cursor clamps to current tail";
        needle = "cursor.next_sequence.min(current_tail.next_sequence)";
      }
      {
        label = "retained replay uses bounded batches";
        needle = ".take(SESSION_EVENT_LOG_REPLAY_BATCH_SIZE)";
      }
      {
        label = "retained replay seeks by cursor";
        needle = "entries.partition_point(|entry| entry.sequence() < cursor.next_sequence)";
      }
      {
        label = "broadcast send is non-fatal";
        needle = "let _ = self.inner.tail.send(frame);";
      }
      {
        label = "actor exposes hub";
        needle = "pub fn event_log(&self) -> SessionEventLog";
      }
      {
        label = "actor exposes direct stream helper";
        needle = "pub fn event_log_stream(&self, cursor: EventLogCursor) -> SessionEventLogStream";
      }
      {
        label = "running quantum publishes entries";
        needle = "self.event_log.append_entries(entries);";
      }
      {
        label = "actor yields after quantum";
        needle = "tokio::task::yield_now().await;";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_control_responsive.rs" sessionGate [
      {
        label = "live stream gate test";
        needle = "gate_control_plane_streams_event_log_entries_from_cursor_without_mutation";
      }
      {
        label = "stream subscribes from zero cursor";
        needle = "event_log.subscribe(EventLogCursor::default())";
      }
      {
        label = "future cursor regression stream";
        needle = "event_log.subscribe(EventLogCursor::new(10_000))";
      }
      {
        label = "future cursor clamped to current tail";
        needle = "assert_eq!(future_stream.cursor(), EventLogCursor::default());";
      }
      {
        label = "causal stream assertion";
        needle = "EventClass::Causal";
      }
      {
        label = "observational stream assertion";
        needle = "EventClass::Observational";
      }
      {
        label = "command-source correlation assertion";
        needle = "EventSource::Command";
      }
      {
        label = "determinism comparison ignores stream observation";
        needle = "compare_event_log_determinism";
      }
      {
        label = "cursor replay path";
        needle = "let cursor = EventLogCursor::new(1);";
      }
      {
        label = "subscribe unsubscribe does not mutate snapshot";
        needle = "drop(observation_only);";
      }
      {
        label = "observational diagnostic emitted";
        needle = "SchedulerEventLogPayload::Diagnostic";
      }
      {
        label = "command control fault entry emitted";
        needle = "Decision::ControlFault(ControlFaultDecision";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "event-log stream module";
        needle = "pub mod event_log_stream;";
      }
      {
        label = "control-plane stream facade export";
        needle = "ControlPlaneEventLog";
      }
      {
        label = "cursor export";
        needle = "EventLogCursor";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/event_log_stream.rs" apiStream [
      {
        label = "control-plane stream facade";
        needle = "pub struct ControlPlaneEventLog";
      }
      {
        label = "session hub re-export";
        needle = "SessionEventLog as SessionEventLogHub";
      }
      {
        label = "current cursor API";
        needle = "pub fn current_cursor(&self) -> EventLogCursor";
      }
      {
        label = "API current cursor delegates to session hub";
        needle = "self.hub.current_cursor()";
      }
      {
        label = "API subscribe delegates to session hub";
        needle = "self.hub.subscribe(cursor)";
      }
      {
        label = "replay batch export";
        needle = "SESSION_EVENT_LOG_REPLAY_BATCH_SIZE";
      }
      {
        label = "stream frame export";
        needle = "SessionEventLogFrame";
      }
      {
        label = "stream error export";
        needle = "SessionEventLogStreamError";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_responsive.rs" apiGate [
      {
        label = "API stream test";
        needle = "gate_control_plane_event_log_stream_api_subscribes_without_mutation";
      }
      {
        label = "API facade exercised";
        needle = "ControlPlaneEventLog::new(actor.event_log())";
      }
      {
        label = "API cursor exercised";
        needle = "before_subscribe.event_log_len.saturating_add(10_000)";
      }
      {
        label = "API future cursor clamping assertion";
        needle = "assert_eq!(stream.cursor(), EventLogCursor::default());";
      }
      {
        label = "API subscription snapshot non-mutation assertion";
        needle = "assert_eq!(after_subscribe, before_subscribe);";
      }
      {
        label = "API stream receive exercised";
        needle = ".recv()";
      }
      {
        label = "API causal delivery assertion";
        needle = "saw_causal";
      }
      {
        label = "API observational delivery assertion";
        needle = "saw_observational";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 event-log control-plane streaming import";
        needle = "eventLogControlPlaneStreaming = import ./phase4-event-log-control-plane-streaming.nix";
      }
      {
        label = "phase4 event-log control-plane streaming attr path";
        needle = "checks.crucible.phase4.eventLogControlPlaneStreaming";
      }
      {
        label = "phase4 event-log control-plane streaming task id";
        needle = "taskIds = [\"T-OBS-11\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log control-plane streaming check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-control-plane-streaming";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

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
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-event-log-control-plane-streaming";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-control-plane-streaming-target" \
              -p crucible-session \
              --test gate_control_responsive \
              gate_control_plane_streams_event_log_entries_from_cursor_without_mutation \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-control-plane-streaming-target" \
              -p crucible-api \
              --test gate_control_responsive \
              gate_control_plane_event_log_stream_api_subscribes_without_mutation \
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
            cursor_stream=single-log
            classes=causal,observational
            command_correlation=EventSource::Command
            observation=non-mutating
            RESULT
          '';
        }
      ];
    }
