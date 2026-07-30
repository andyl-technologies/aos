{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionProximityGradient",
  taskIds ? ["T-ASRT-18"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  proximityTest = builtins.readFile ../../crates/crucible/tests/assertion_proximity_gradient.rs;
  evaluationOrderTest = builtins.readFile ../../crates/crucible/tests/assertion_evaluation_order.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-18 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionProximityGradient`";
      }
      {
        label = "single-VM fingerprint gate named";
        needle = "`checks.crucible.phase1.gates.singleVmFingerprint`";
      }
      {
        label = "replay oracle gate named";
        needle = "`checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "OBS-37 assertion proximity projection";
        needle = "assertion-proximity **distance-to-satisfaction**";
      }
      {
        label = "OBS-37 event kind";
        needle = "observational `assertion_proximity` kind";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedDoc [
      {
        label = "guided search consumer";
        needle = "AssertionProximity— the distance-to-assertion metric defined in 18";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "proximity report type";
        needle = "pub struct HostAssertionProximity";
      }
      {
        label = "proximity report accessor";
        needle = "pub fn proximities(&self) -> &[HostAssertionProximity]";
      }
      {
        label = "proximity stored outside verdict fields";
        needle = "proximities: Vec<HostAssertionProximity>";
      }
      {
        label = "boolean unit distance";
        needle = "const ASSERTION_PROXIMITY_UNIT: u128 = 1;";
      }
      {
        label = "unobserved numeric sentinel";
        needle = "const ASSERTION_PROXIMITY_UNOBSERVED_NUMERIC: u128 = u128::MAX;";
      }
      {
        label = "structural distance evaluator";
        needle = "fn condition_distance_to_satisfaction";
      }
      {
        label = "all-of sums child distances";
        needle = "sum.saturating_add(condition_distance_to_satisfaction(evaluator, predicate))";
      }
      {
        label = "any-of selects minimum distance";
        needle = ".min()\n            .unwrap_or(ASSERTION_PROXIMITY_UNIT)";
      }
      {
        label = "numeric threshold gap";
        needle = "fn memory_cmp_distance_to_satisfaction";
      }
      {
        label = "proximity reportability filter";
        needle = "fn property_proximity_is_reportable";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_proximity_gradient.rs" proximityTest [
      {
        label = "T-ASRT-18 regression module";
        needle = "Checks T-ASRT-18 assertion proximity gradient reporting.";
      }
      {
        label = "minimum threshold gap test";
        needle = "proximity_gradient_folds_minimum_threshold_gap_for_unsatisfied_sometimes";
      }
      {
        label = "boolean unit fallback test";
        needle = "proximity_gradient_reports_boolean_unit_for_unreached_boolean_conditions";
      }
      {
        label = "armed eventually test";
        needle = "proximity_gradient_tracks_armed_eventually_without_changing_verdict";
      }
      {
        label = "satisfied omission test";
        needle = "proximity_gradient_omits_satisfied_and_never_triggered_obligations";
      }
      {
        label = "online offline equality";
        needle = "assert_eq!(offline, online)";
      }
      {
        label = "verdict unchanged";
        needle = "AssertionRunVerdict::Failed";
      }
      {
        label = "minimum distance assertion";
        needle = "assert_eq!(proximity.distance, 3);";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_evaluation_order.rs" evaluationOrderTest [
      {
        label = "proximity does not re-enter named leaves";
        needle = "eventually_trigger_and_property_share_one_named_leaf_evaluation_per_point";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion proximity import";
        needle = "assertionProximityGradient = import ./phase4-assertion-proximity-gradient.nix";
      }
      {
        label = "phase4 assertion proximity attr path";
        needle = "attrPath = \"checks.crucible.phase4.assertionProximityGradient\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/assertion_proximity_gradient.rs" proximityTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
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
  then throw "crucible phase4 assertion-proximity-gradient check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-assertion-proximity-gradient";
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
          name = "run-assertion-proximity-gradient";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-assertion-proximity-gradient-target" \
              -p crucible \
              --features test-double \
              --test assertion_proximity_gradient \
              --test assertion_evaluation_order \
              --test assertion_log_fold \
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
            assertion_proximity=steering-only-report-projection
            distance_fold=minimum-over-event-log-trajectory
            verdict_effect=none
            oracle_effect=none
            replay_effect=online-offline-identical
            fingerprint_effect=none
            RESULT
          '';
        }
      ];
    }
