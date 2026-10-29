{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.advancedDependencyLadder",
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  testingGatesPage = builtins.readFile ../../docs/engineering/crucible/testing-and-gates.md;
  phasePlanRust = builtins.readFile ../../crates/crucible/crucible-test-support/src/phase_plan.rs;
  phasePlanTest = builtins.readFile ../../crates/crucible/crucible-test-support/tests/phase_plan.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/engineering/crucible/testing-and-gates.md" testingGatesPage [
      {
        label = "dependency order prose";
        needle = "exact-determinism -> save-restore -> fork -> search -> coverage-feedback -> fuzzing";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/src/phase_plan.rs" phasePlanRust [
      {
        label = "advanced rung enum";
        needle = "pub enum AdvancedFeatureRung";
      }
      {
        label = "advanced ladder table";
        needle = "pub const ADVANCED_FEATURE_LADDER";
      }
      {
        label = "advanced ladder function";
        needle = "pub fn advanced_feature_ladder_failures";
      }
      {
        label = "advanced schedule function";
        needle = "pub fn advanced_feature_schedule_failures";
      }
      {
        label = "determinism foundation";
        needle = "checks.crucible.phase4.gates.e2eDeterminism";
      }
      {
        label = "replay foundation";
        needle = "checks.crucible.phase4.gates.replayOracle";
      }
      {
        label = "control foundation";
        needle = "checks.crucible.phase5.gates.controlResponsive";
      }
      {
        label = "fuzzing ladder step";
        needle = ''attr_path: "checks.crucible.phase6.coverageGuidedFuzzing"'';
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/tests/phase_plan.rs" phasePlanTest [
      {
        label = "canonical advanced ladder test";
        needle = "advanced_feature_ladder_keeps_fuzzing_above_search_and_coverage";
      }
      {
        label = "actual default schedule test";
        needle = "advanced_feature_schedule_rejects_unwrapped_default_check";
      }
      {
        label = "inner dependency negative test";
        needle = "advanced_feature_schedule_rejects_inner_only_gate_dependency";
      }
      {
        label = "borrowed guard negative test";
        needle = "advanced_feature_schedule_rejects_check_borrowing_a_nearby_guard";
      }
      {
        label = "fuzz-before-coverage negative test";
        needle = "advanced_feature_ladder_rejects_fuzzing_before_coverage";
      }
      {
        label = "late foundation negative test";
        needle = "advanced_feature_ladder_rejects_steps_before_foundation_gates";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase6 advanced ladder green wrapper";
        needle = "advancedDependencyLadder = greenBeforeAdvance";
      }
      {
        label = "phase6 advanced ladder import";
        needle = "gate = import ./phase6-advanced-dependency-ladder.nix";
      }
      {
        label = "phase6 advanced ladder attr path";
        needle = "checks.crucible.phase6.advancedDependencyLadder";
      }
      {
        label = "phase6 advanced ladder raw fingerprint dependency";
        needle = "phase2.gates.singleVmFingerprint.rawGate";
      }
      {
        label = "phase6 advanced ladder green fingerprint dependency";
        needle = "phase2.gates.singleVmFingerprint";
      }
      {
        label = "phase6 advanced ladder raw replay dependency";
        needle = "phase4.gates.replayOracle.rawGate";
      }
      {
        label = "phase6 advanced ladder green replay dependency";
        needle = "phase4.gates.replayOracle";
      }
      {
        label = "phase6 advanced ladder green e2e dependency";
        needle = "phase4.gates.e2eDeterminism";
      }
      {
        label = "phase6 advanced ladder green control dependency";
        needle = "phase5.gates.controlResponsive";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 advanced dependency ladder check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-advanced-dependency-ladder";
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
          name = "run-advanced-dependency-ladder";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-advanced-dependency-ladder-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-test-support \
              --test phase_plan \
              advanced_feature \
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
            ladder=exact-determinism,save-restore,fork,search,coverage-feedback,fuzzing
            rust_test=crucible_test_support::phase_plan::advanced_feature
            RESULT
          '';
        }
      ];
    }
