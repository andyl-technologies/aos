{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.reproductionArtifacts",
  taskIds ? ["T-ADV-14"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  libRs = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  artifactTest = builtins.readFile ../../crates/crucible/tests/gate_reproduction_artifacts.rs;
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
        label = "T-ADV-14 completion note";
        needle = "Completed by `checks.crucible.phase6.reproductionArtifacts`";
      }
      {
        label = "ADV-28 every finding artifact";
        needle = "Every interesting finding (a property violation, a divergence, a\n  concrete execution timeout, or a retained corpus entry) MUST emit a\n  self-contained reproduction artifact";
      }
      {
        label = "ADV-29 discovery paths";
        needle = "regardless of how\n  the finding was reached (campaign branching, state-space search, or\n  coverage-guided fuzzing)";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "discovery path enum";
        needle = "pub enum FindingDiscoveryPath";
      }
      {
        label = "finding artifact type";
        needle = "pub struct FindingReproductionArtifact";
      }
      {
        label = "capture API";
        needle = "pub fn capture(";
      }
      {
        label = "load from store API";
        needle = "pub fn load_from_store";
      }
      {
        label = "campaign branch hook";
        needle = "FindingDiscoveryPath::CampaignFork";
      }
      {
        label = "search failure hook";
        needle = "FindingDiscoveryPath::StateSpaceSearch";
      }
      {
        label = "search failure stores artifact";
        needle = "reproduction_artifact: FindingReproductionArtifact";
      }
      {
        label = "fuzz iteration hook";
        needle = "FindingDiscoveryPath::CoverageGuidedFuzzing";
      }
      {
        label = "retained corpus hook";
        needle = "FindingDiscoveryPath::RetainedCorpusEntry";
      }
      {
        label = "retained corpus descriptor guard";
        needle = "RetainedCorpusEntryMismatch";
      }
      {
        label = "scenario mismatch guard";
        needle = "ReproductionScenarioMismatch";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "discovery path export";
        needle = "FindingDiscoveryPath";
      }
      {
        label = "finding artifact export";
        needle = "FindingReproductionArtifact";
      }
      {
        label = "finding artifact error export";
        needle = "FindingReproductionArtifactError";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_reproduction_artifacts.rs" artifactTest [
      {
        label = "interactive/search gate";
        needle = "gate_findings_emit_same_artifact_for_interactive_and_search_paths";
      }
      {
        label = "fuzz/corpus gate";
        needle = "gate_fuzz_and_retained_corpus_artifacts_replay_without_campaign";
      }
      {
        label = "interactive hook assertion";
        needle = "fork.reproduction_artifact";
      }
      {
        label = "search hook assertion";
        needle = "search_failure.reproduction_artifact";
      }
      {
        label = "real search failure path";
        needle = "search_with_strategy_and_failure_oracle";
      }
      {
        label = "fuzz hook assertion";
        needle = "reproduction_artifact(finding_fingerprint(\"fuzz-finding\"))";
      }
      {
        label = "store reload assertion";
        needle = "FindingReproductionArtifact::load_from_store";
      }
      {
        label = "retained corpus hook assertion";
        needle = "retained.reproduction_artifact";
      }
      {
        label = "retained corpus descriptor mismatch assertion";
        needle = "FindingReproductionArtifactError::RetainedCorpusEntryMismatch";
      }
      {
        label = "scenario mismatch assertion";
        needle = "EngineError::ReproductionScenarioMismatch";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green reproduction artifact gate";
        needle = "reproductionArtifacts = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-ADV-14\"]";
      }
      {
        label = "corpus raw dependency";
        needle = "phase6.coverageGuidedCorpus.rawGate";
      }
      {
        label = "corpus green dependency";
        needle = "phase6.coverageGuidedCorpus";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_reproduction_artifacts.rs" artifactTest [
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
  then throw "crucible phase6 reproduction-artifacts check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase6-reproduction-artifacts";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "run-reproduction-artifacts";
          script = ''
            set -eu
            crucible-cargo test \
              -p crucible \
              --test gate_reproduction_artifacts \
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
            gate=gate:reproduction-artifacts
            artifact=self-contained-seed-scenario-schedule
            paths=campaign-fork,state-space-search,coverage-guided-fuzzing,retained-corpus
            replay=store-independent
            RESULT
          '';
        }
      ];
    }
