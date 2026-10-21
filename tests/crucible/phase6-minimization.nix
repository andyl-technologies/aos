{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.minimization",
  taskIds ? ["T-ADV-15"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  libRs = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  minimizationTest = builtins.readFile ../../crates/crucible/tests/gate_minimization.rs;
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
        label = "T-ADV-15 completion note";
        needle = "Completed by `checks.crucible.phase6.minimization`";
      }
      {
        label = "ADV-30 shrinking pass";
        needle = "Crucible MUST provide a minimization (shrinking) pass";
      }
      {
        label = "ADV-31 deterministic candidate order";
        needle = "candidate-shrink order MUST\n  be a seeded, content-address-tie-broken function";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "minimization config";
        needle = "pub struct MinimizationConfig";
      }
      {
        label = "minimization attempt report";
        needle = "pub struct MinimizationAttempt";
      }
      {
        label = "minimization run report";
        needle = "pub struct MinimizationRun";
      }
      {
        label = "finding minimization API";
        needle = "pub fn minimize<F>";
      }
      {
        label = "seeded candidate key";
        needle = "fn minimization_candidate_key";
      }
      {
        label = "deterministic minimization candidate generator";
        needle = "pub(super) fn minimization_candidates(";
      }
      {
        label = "schedule constructor";
        needle = "pub fn from_decisions";
      }
      {
        label = "starting artifact validation";
        needle = "fn validated(&self) -> Result<Self, EngineError>";
      }
      {
        label = "candidate replay capture";
        needle = "FindingReproductionArtifact::capture";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "minimization config export";
        needle = "MinimizationConfig";
      }
      {
        label = "minimization attempt export";
        needle = "MinimizationAttempt";
      }
      {
        label = "minimization run export";
        needle = "MinimizationRun";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_minimization.rs" minimizationTest [
      {
        label = "deterministic shrink gate";
        needle = "gate_minimization_shrinks_schedule_and_rng_decisions_deterministically";
      }
      {
        label = "non reproducing start gate";
        needle = "gate_minimization_rejects_non_reproducing_start";
      }
      {
        label = "seeded config use";
        needle = "MinimizationConfig::new";
      }
      {
        label = "failure fingerprint oracle";
        needle = "failure_oracle";
      }
      {
        label = "real assertion fold oracle";
        needle = "OfflineAssertionChecker::new";
      }
      {
        label = "retained assertion log";
        needle = "RecordedAssertionLog::from_segments";
      }
      {
        label = "oracle fingerprint from assertion violation";
        needle = "assertion_fold_failure_fingerprint";
      }
      {
        label = "stable repeated run assertion";
        needle = "assert_eq!(first, second)";
      }
      {
        label = "unused RNG decision removed";
        needle = "rng_decision(\"unused-network-draw\", 0)";
      }
      {
        label = "minimal schedule assertion";
        needle = "assert_eq!(minimized_schedule.len(), 1)";
      }
      {
        label = "removed index set";
        needle = "accepted.removed_indices.len()";
      }
      {
        label = "forged artifact validation";
        needle = "gate_minimization_validates_public_artifact_before_oracle";
      }
      {
        label = "replay mismatch rejection";
        needle = "EngineError::ReproductionArtifactReplayMismatch";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green minimization gate";
        needle = "minimization = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-ADV-15\"]";
      }
      {
        label = "reproduction raw dependency";
        needle = "phase6.reproductionArtifacts.rawGate";
      }
      {
        label = "reproduction green dependency";
        needle = "phase6.reproductionArtifacts";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_minimization.rs" minimizationTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 minimization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase6-minimization";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "run-minimization";
          script = ''
            set -eu
            crucible-cargo test \
              -p crucible \
              --test gate_minimization \
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
            gate=gate:minimization
            artifact=stable-minimized-reproduction
            order=seeded-content-address
            oracle=failure-fingerprint-preserving
            RESULT
          '';
        }
      ];
    }
