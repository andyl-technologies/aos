{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.advancedDependencyLadder",
  taskIds ? ["T-ADV-1"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  phasePlanRust = builtins.readFile ../../crates/crucible-harness/src/phase_plan.rs;
  phasePlanTest = builtins.readFile ../../crates/crucible-harness/tests/phase_plan.rs;
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
    failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedDoc [
      {
        label = "T-ADV-1 checked off";
        needle = "- [x] **T-ADV-1**";
      }
      {
        label = "T-ADV-1 completion note";
        needle = "Completed by `checks.crucible.phase6.advancedDependencyLadder`";
      }
      {
        label = "dependency order prose";
        needle = "exact-determinism →";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/phase_plan.rs" phasePlanRust [
      {
        label = "advanced rung enum";
        needle = "pub enum AdvancedFeatureRung";
      }
      {
        label = "advanced task table";
        needle = "pub const ADVANCED_FEATURE_TASK_ORDER";
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
        label = "fuzzing waits for coverage";
        needle = ''required_task_ids: &["T-ADV-11", "T-ADV-19", "T-ADV-21"]'';
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/phase_plan.rs" phasePlanTest [
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
        label = "implicit task id negative test";
        needle = "advanced_feature_schedule_rejects_phase6_import_without_explicit_task_ids";
      }
      {
        label = "fuzz-before-coverage negative test";
        needle = "advanced_feature_ladder_rejects_fuzzing_before_coverage";
      }
      {
        label = "late foundation negative test";
        needle = "advanced_feature_ladder_rejects_tasks_before_foundation_gates";
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
        label = "phase6 advanced ladder task id";
        needle = ''taskIds = ["T-ADV-1"]'';
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
              -p crucible-harness \
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
            tasks=${taskList}
            ladder=exact-determinism,save-restore,fork,search,coverage-feedback,fuzzing
            rust_test=crucible-harness::phase_plan::advanced_feature
            RESULT
          '';
        }
      ];
    }
