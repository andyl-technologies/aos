{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.explorationLifecycle",
  taskIds ? ["T-ADV-2"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  lifecycleGateTest = builtins.readFile ../../crates/crucible-session/tests/gate_exploration_lifecycle.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedDoc [
      {
        label = "T-ADV-2 completion note";
        needle = "Completed by `checks.crucible.phase6.explorationLifecycle`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "exploration lifecycle driver";
        needle = "pub struct ExplorationLifecycleDriver";
      }
      {
        label = "session-command sender ownership";
        needle = "sender: mpsc::Sender<SessionCommand>";
      }
      {
        label = "live snapshot observation";
        needle = "live: Arc<LiveSnapshot>";
      }
      {
        label = "one quantum lifecycle bound";
        needle = "pub const EXPLORATION_LIFECYCLE_RESPONSE_BOUND_QUANTA: u64 = 1;";
      }
      {
        label = "acknowledgement quantum helper";
        needle = "acknowledgement_delta_quanta";
      }
      {
        label = "pause routed as session command";
        needle = "SessionCommand::Pause";
      }
      {
        label = "resume routed as continue command";
        needle = "SessionCommand::Continue";
      }
      {
        label = "stop routed as session command";
        needle = "SessionCommand::Stop";
      }
      {
        label = "mailbox issue path";
        needle = ".send(session_command)";
      }
      {
        label = "running pause precondition";
        needle = "LiveStateKind::Running";
      }
      {
        label = "paused resume precondition";
        needle = "LiveStateKind::Paused";
      }
      {
        label = "stopped acknowledgement";
        needle = "LiveStateKind::Stopped";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "wall-clock lifecycle timeout type";
        needle = "LifecycleWallClockTimeout";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_exploration_lifecycle.rs" lifecycleGateTest [
      {
        label = "session command route test";
        needle = "exploration_lifecycle_driver_routes_pause_resume_stop_as_session_commands";
      }
      {
        label = "bit-identical resume test";
        needle = "pause_resume_continue_matches_uninterrupted_canonical_run";
      }
      {
        label = "no scheduler control injection";
        needle = "pause/resume/stop must not be injected as scheduler-owned control operations";
      }
      {
        label = "uninterrupted comparison";
        needle = "run_uninterrupted";
      }
      {
        label = "schedule equality";
        needle = "report.final_snapshot.configuration.schedule";
      }
      {
        label = "event-log replay";
        needle = "assert_event_log_replay_is_exact";
      }
      {
        label = "event-log payload equality";
        needle = "frame.entry, *expected_entry";
      }
      {
        label = "resume does not append canonical entries";
        needle = "resume.requested_event_log_len, resume.acknowledged_event_log_len";
      }
      {
        label = "stop from pause does not append canonical entries";
        needle = "stop.requested_event_log_len, stop.acknowledged_event_log_len";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-session/tests/gate_exploration_lifecycle.rs" lifecycleGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase6 lifecycle green wrapper";
        needle = "explorationLifecycle = greenBeforeAdvance";
      }
      {
        label = "phase6 lifecycle import";
        needle = "gate = import ./phase6-exploration-lifecycle.nix";
      }
      {
        label = "phase6 lifecycle attr path";
        needle = "checks.crucible.phase6.explorationLifecycle";
      }
      {
        label = "phase6 lifecycle task id";
        needle = ''taskIds = ["T-ADV-2"]'';
      }
      {
        label = "phase6 lifecycle raw control dependency";
        needle = "phase5.gates.controlResponsive.rawGate";
      }
      {
        label = "phase6 lifecycle raw advanced ladder dependency";
        needle = "phase6.advancedDependencyLadder.rawGate";
      }
      {
        label = "phase6 lifecycle green control dependency";
        needle = "phase5.gates.controlResponsive";
      }
      {
        label = "phase6 lifecycle green advanced ladder dependency";
        needle = "phase6.advancedDependencyLadder";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 exploration lifecycle check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-exploration-lifecycle";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-exploration-lifecycle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-exploration-lifecycle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-session \
              --test gate_exploration_lifecycle \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
                        set -eu
                        mkdir -p "$out"
                        cat > "$out/result" <<RESULT
                        PASS
            check=${attrPath}
            tasks=${taskList}
            lifecycle=pause,resume,stop
            rust_test=crucible-session::gate_exploration_lifecycle
            RESULT
          '';
        }
      ];
    }
