{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionLockFreeObservation",
  taskIds ? ["T-SESS-10"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  sessionGateTest = builtins.readFile ../../crates/crucible-session/tests/gate_control_responsive.rs;
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-10 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionLockFreeObservation`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 lock-free observation status note";
        needle = "`T-SESS-10` is green through `checks.crucible.phase5.sessionLockFreeObservation`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "lock-free live snapshot type";
        needle = "pub struct LiveSnapshot";
      }
      {
        label = "seqlock epoch atomic";
        needle = "epoch: AtomicU64";
      }
      {
        label = "state-kind atomic";
        needle = "state_kind: AtomicU8";
      }
      {
        label = "virtual-time atomic";
        needle = "virtual_time_ticks: AtomicU64";
      }
      {
        label = "event-log length atomic";
        needle = "event_log_len: AtomicU64";
      }
      {
        label = "quanta counter atomic";
        needle = "quanta_stepped: AtomicU64";
      }
      {
        label = "lock-free read API";
        needle = "pub fn read(&self) -> LiveSnapshotView";
      }
      {
        label = "lock-free read acquire ordering";
        needle = "Ordering::Acquire";
      }
      {
        label = "actor-owned snapshot publisher";
        needle = "fn publish(&self, snapshot: &EngineSnapshot";
      }
      {
        label = "direct actor live status read";
        needle = "pub fn live_status(&self) -> LiveSnapshotView";
      }
      {
        label = "direct actor live status uses mirror";
        needle = "self.live.read()";
      }
      {
        label = "lock-free query kind";
        needle = "pub enum LiveQueryKind";
      }
      {
        label = "lock-free query result";
        needle = "pub enum LiveQueryResult";
      }
      {
        label = "lock-free query API";
        needle = "pub fn query(&self, kind: LiveQueryKind) -> LiveQueryResult";
      }
      {
        label = "lock-free status query";
        needle = "LiveQueryKind::Status => LiveQueryResult::Status(view)";
      }
      {
        label = "lock-free state query";
        needle = "LiveQueryKind::State => LiveQueryResult::State(view.lifecycle_state())";
      }
      {
        label = "lock-free event-log-length query";
        needle = "LiveQueryKind::EventLogLength => LiveQueryResult::EventLogLength(view.event_log_len)";
      }
      {
        label = "bounded event-log broadcast capacity";
        needle = "SESSION_EVENT_LOG_BROADCAST_CAPACITY";
      }
      {
        label = "event-log broadcast channel";
        needle = "broadcast::channel(SESSION_EVENT_LOG_BROADCAST_CAPACITY)";
      }
      {
        label = "event-log stream lag resumes retained replay";
        needle = "self.resume_from_retained_log();";
      }
      {
        label = "actor event-log stream API";
        needle = "pub fn event_log_stream(&self, cursor: EventLogCursor) -> SessionEventLogStream";
      }
      {
        label = "bounded state-transition broadcast capacity";
        needle = "SESSION_STATE_BROADCAST_CAPACITY";
      }
      {
        label = "state-transition frame";
        needle = "pub struct SessionStateTransitionFrame";
      }
      {
        label = "state-transition frame carries full from-state";
        needle = "pub from_state: EngineState";
      }
      {
        label = "state-transition frame carries full to-state";
        needle = "pub to_state: EngineState";
      }
      {
        label = "state-transition bus";
        needle = "pub struct SessionStateTransitionBus";
      }
      {
        label = "state-transition stream";
        needle = "pub struct SessionStateTransitionStream";
      }
      {
        label = "state-transition broadcast channel";
        needle = "broadcast::channel(SESSION_STATE_BROADCAST_CAPACITY)";
      }
      {
        label = "state-transition stream lag error";
        needle = "SessionStateTransitionStreamError::Lagged";
      }
      {
        label = "actor owns state-transition bus";
        needle = "state_transitions: SessionStateTransitionBus";
      }
      {
        label = "actor tracks last published full state";
        needle = "last_published_state: EngineState";
      }
      {
        label = "actor exposes state-transition bus";
        needle = "pub fn state_transition_bus(&self) -> SessionStateTransitionBus";
      }
      {
        label = "actor exposes state-transition stream";
        needle = "pub fn state_transition_stream(&self) -> SessionStateTransitionStream";
      }
      {
        label = "transition sequence";
        needle = "state_transition_sequence";
      }
      {
        label = "full state transition detection";
        needle = "before_state != after_state";
      }
      {
        label = "state-transition publish";
        needle = "self.state_transitions.publish";
      }
      {
        label = "direct live-query test";
        needle = "session_actor_live_query_reads_atomic_mirror_without_mailbox_query";
      }
      {
        label = "state-transition broadcast test";
        needle = "session_actor_state_transition_bus_broadcasts_actor_owned_transitions";
      }
      {
        label = "state-transition lag test";
        needle = "session_state_transition_stream_reports_lag_without_backpressure";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_control_responsive.rs" sessionGateTest [
      {
        label = "live snapshot gate";
        needle = "gate_control_responsive_reads_live_snapshot_without_mailbox_roundtrip";
      }
      {
        label = "live status query gate";
        needle = "live.query(LiveQueryKind::Status)";
      }
      {
        label = "live state query gate";
        needle = "live.query(LiveQueryKind::State)";
      }
      {
        label = "live event-log-length query gate";
        needle = "live.query(LiveQueryKind::EventLogLength)";
      }
      {
        label = "event-log stream gate";
        needle = "gate_control_plane_streams_event_log_entries_from_cursor_without_mutation";
      }
      {
        label = "state-transition stream gate";
        needle = "gate_control_plane_streams_state_transitions_without_mailbox_roundtrip";
      }
      {
        label = "public state-transition bus subscription";
        needle = "let state_transitions = actor.state_transition_bus();";
      }
      {
        label = "observation-only subscription";
        needle = "let observation_only = state_transitions.subscribe();";
      }
      {
        label = "state-transition full state gate";
        needle = "assert_eq!(started.from_state, EngineState::Loaded);";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session lock-free observation check";
        needle = "sessionLockFreeObservation = import ./phase5-session-lock-free-observation.nix";
      }
      {
        label = "phase5 lock-free observation attr path";
        needle = ''attrPath = "checks.crucible.phase5.sessionLockFreeObservation"'';
      }
      {
        label = "phase5 lock-free observation task id";
        needle = ''taskIds = ["T-SESS-10"]'';
      }
      {
        label = "phase5 lock-free observation depends on control determinism";
        needle = "dependencies = [phase5.sessionControlDeterminism]";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session-lock-free-observation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-lock-free-observation";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
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
          name = "run-session-lock-free-observation";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-lock-free-observation-target" \
              -p crucible-session \
              --lib \
              --test gate_control_responsive \
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
            mirror=lock-free-atomics
            event_log_broadcast=lag-or-drop
            state_transition_broadcast=lag-or-drop
            actor_mailbox_observation=false
            RESULT
          '';
        }
      ];
    }
