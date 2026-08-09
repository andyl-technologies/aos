{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.replayOracle",
  taskIds ? ["T-TRIG-20" "T-ASRT-16" "T-ASRT-18"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  replayTest = builtins.readFile ../../crates/crucible/tests/event_graph_replay_oracle.rs;
  replayGate = builtins.readFile ../../crates/crucible/tests/gate_replay_oracle.rs;
  assertionProximityTest = builtins.readFile ../../crates/crucible/tests/assertion_proximity_gradient.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  assertionsDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;
  e2eGate = builtins.readFile ./phase4-e2e-determinism.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-20 completion note";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionsDoc [
      {
        label = "T-ASRT-16 completion note";
        needle = "Completed by `checks.crucible.phase4.gates.e2eDeterminism` and";
      }
      {
        label = "T-ASRT-18 replay completion note";
        needle = "`checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_graph_replay_oracle.rs" replayTest [
      {
        label = "identical replay/e2e test";
        needle = "event_graph_replay_oracle_rederives_identical_firings_actions_and_verdict";
      }
      {
        label = "first divergence localization test";
        needle = "event_graph_replay_oracle_localizes_first_differing_firing";
      }
      {
        label = "first firing divergence helper";
        needle = "fn first_trigger_firing_divergence";
      }
      {
        label = "offline action replay helper";
        needle = "fn replay_trigger_applications_from_event_log";
      }
      {
        label = "condition script content hash";
        needle = "fn condition_script_hash";
      }
      {
        label = "condition script schedule anchor";
        needle = "fn event_graph_replay_schedule";
      }
      {
        label = "condition script recorded as schedule decision";
        needle = "Decision::Override";
      }
      {
        label = "condition script schedule drift check";
        needle = "condition_script_matches_recorded_schedule";
      }
      {
        label = "condition script drift rejection test";
        needle = "event_graph_replay_oracle_rejects_condition_script_schedule_drift";
      }
      {
        label = "scenario form identity";
        needle = "ScenarioDefForm::from_components";
      }
      {
        label = "plan-carried graph replay";
        needle = "plan should carry the event graph under replay";
      }
      {
        label = "self-contained reproduction artifact";
        needle = "ReproductionArtifact::capture";
      }
      {
        label = "artifact replay helper";
        needle = "fn replay_event_graph_artifact";
      }
      {
        label = "offline event-graph replay oracle";
        needle = "fn check_event_graph_replay_oracle";
      }
      {
        label = "fixed scenario seed comparison";
        needle = "assert_eq!(online.scenario_seed, offline.scenario_seed)";
      }
      {
        label = "fixed schedule comparison";
        needle = "assert_eq!(online.schedule, offline.schedule)";
      }
      {
        label = "fixed condition script comparison";
        needle = "assert_eq!(online.condition_script_hash, offline.condition_script_hash)";
      }
      {
        label = "artifact schedule anchor";
        needle = "artifact.reproduction.schedule()";
      }
      {
        label = "trigger firing entry replay";
        needle = "SchedulerEventLogPayload::TriggerFired";
      }
      {
        label = "trigger action entry replay";
        needle = "SchedulerEventLogPayload::TriggerActionApplied";
      }
      {
        label = "online/offline verdict replay";
        needle = "TriggerActionState::compose_run_verdict_from_event_log";
      }
      {
        label = "event-log content hash validation";
        needle = "entry.has_valid_content_hash()";
      }
      {
        label = "pass action";
        needle = "Action::pass";
      }
      {
        label = "fail action";
        needle = "Action::fail";
      }
      {
        label = "identical prefix assertion";
        needle = "replay oracle must preserve the identical prefix before reporting divergence";
      }
      {
        label = "no guest-side fallback oracle";
        needle = "struct NoGuestLeaves";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_replay_oracle.rs" replayGate [
      {
        label = "assertion replay-oracle coverage test";
        needle = "gate_replay_oracle_covers_assertion_regrade_and_violation_reproduction";
      }
      {
        label = "assertion retained corpus regrade";
        needle = "gate:replay-oracle must idempotently re-grade a retained assertion corpus";
      }
      {
        label = "artifact-bound assertion violation replay";
        needle = "check_assertion_violation_reproduction(&artifact, &recorded_log, &replayed)";
      }
      {
        label = "assertion retained corpus grows";
        needle = "gate:replay-oracle must idempotently re-grade retained runs after assertion suites grow";
      }
      {
        label = "artifact-derived assertion log";
        needle = "assertion_replay_recorded_log_from_artifact(&artifact)";
      }
      {
        label = "bit-identical artifact assertion log";
        needle = "artifact-bound assertion replay must emit a bit-identical retained log";
      }
      {
        label = "assertion replay schedule drift guard";
        needle = "assertion replay log must be derived from the artifact schedule, not a cloned fixture";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_proximity_gradient.rs" assertionProximityTest [
      {
        label = "assertion proximity online/offline equality";
        needle = "assert_eq!(offline, online)";
      }
      {
        label = "assertion proximity dedicated test";
        needle = "proximity_gradient_folds_minimum_threshold_gap_for_unsatisfied_sometimes";
      }
      {
        label = "assertion proximity verdict non-effect";
        needle = "proximity_gradient_tracks_armed_eventually_without_changing_verdict";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 replay-oracle gate import";
        needle = "replayOracle = import ./phase4-event-graph-replay-oracle.nix";
      }
      {
        label = "phase4 replay-oracle attr path";
        needle = "attrPath = \"checks.crucible.phase4.gates.replayOracle\"";
      }
      {
        label = "phase4 e2e gate import";
        needle = "e2eDeterminism = import ./phase4-e2e-determinism.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-e2e-determinism.nix" e2eGate [
      {
        label = "real scheduler-backed e2e target";
        needle = "gate_e2e_determinism_concurrency";
      }
      {
        label = "e2e target runs with test-double";
        needle = "--features test-double";
      }
      {
        label = "e2e target scenario metadata";
        needle = "scenario=serial-vs-concurrent-authoritative-drive";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "stale replay gate pending prose";
        needle = "Replay gates remain T-TRIG-20";
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 replay-oracle red gate placeholder";
        needle = "reason = \"full replay oracle gate is intentionally pending\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_graph_replay_oracle.rs" replayTest [
      {
        label = "trigger action decision variant";
        needle = "Decision::Trigger";
      }
      {
        label = "host wall clock";
        needle = "std::time";
      }
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-graph replay-oracle check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-graph-replay-oracle";
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
          name = "run-event-graph-replay-oracle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-graph-replay-oracle-target" \
              -p crucible \
              --features test-double \
              --test assertion_proximity_gradient \
              --test event_graph_replay_oracle \
              --test gate_replay_oracle \
              -- --test-threads=1
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/nix-support"
            {
              echo "attr=${attrPath}"
              echo "tasks=${taskList}"
              echo "gate=phase4-event-graph-replay-oracle"
              echo "replay_oracle=implemented-T-TRIG-20"
              echo "e2e_determinism=covered-by-checks.crucible.phase4.gates.e2eDeterminism"
              echo "fixed_scenario_seed_schedule=true"
              echo "identical_trigger_firings=true"
              echo "identical_trigger_actions=true"
              echo "online_offline_verdict_replay=true"
              echo "first_divergence_localized=true"
              echo "assertion_corpus_regrade=idempotent"
              echo "assertion_corpus_growth_regrade=idempotent"
              echo "assertion_replay_log=artifact-derived"
              echo "assertion_violation_reproduction=bit-identical"
              echo "assertion_proximity_replay=online-offline-identical"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
