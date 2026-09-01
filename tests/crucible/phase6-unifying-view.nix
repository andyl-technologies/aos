{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.unifyingView",
  taskIds ? ["T-ADV-16"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  unifyingTest = builtins.readFile ../../crates/crucible/tests/gate_unifying_view.rs;
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
        label = "T-ADV-16 completion note";
        needle = "Completed by `checks.crucible.phase6.unifyingView`";
      }
      {
        label = "ADV-32 single graph";
        needle = "MUST all be operations on the single\n  content-addressed temporal graph";
      }
      {
        label = "ADV-32 no second path";
        needle = "There\n  MUST be no abstract specification engine";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "unified operation enum";
        needle = "pub enum UnifiedGraphOperationKind";
      }
      {
        label = "unified operation evidence";
        needle = "pub enum UnifiedGraphOperationEvidence";
      }
      {
        label = "unified operation report";
        needle = "pub struct UnifiedGraphOperationReport";
      }
      {
        label = "unified validation API";
        needle = "pub fn validate_unified_operation";
      }
      {
        label = "operation report validation";
        needle = "operation.validate_report(self, &configuration, &report)?;";
      }
      {
        label = "fork ancestry validation";
        needle = "configuration_prefix_with_id";
      }
      {
        label = "save store key validation";
        needle = "temporal_graph_store_keys_for_configuration";
      }
      {
        label = "state-space search discovery path validation";
        needle = "search-discovery-path";
      }
      {
        label = "state-space search run reconstruction";
        needle = "configuration_from_state_space_search";
      }
      {
        label = "coverage-guided fuzz run reconstruction";
        needle = "coverage_guided_fuzz_run_from_fingerprints";
      }
      {
        label = "minimization transcript validation";
        needle = "configuration_from_minimization_run";
      }
      {
        label = "unified evidence mismatch error";
        needle = "UnifiedOperationEvidenceMismatch";
      }
      {
        label = "single instantiate path";
        needle = "let runtime = instantiate(self, configuration)?;";
      }
      {
        label = "pure reduce comparison";
        needle = "let reduced = reduce(&configuration.def, &configuration.schedule)?;";
      }
      {
        label = "replay oracle validation";
        needle = "self.replay_checkpoint(configuration, &checkpoint)?";
      }
      {
        label = "single VM fingerprint evidence";
        needle = "ExecutionFingerprint { hash: runtime.id }";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "unified operation evidence export";
        needle = "UnifiedGraphOperationEvidence";
      }
      {
        label = "unified operation enum export";
        needle = "UnifiedGraphOperationKind";
      }
      {
        label = "unified operation report export";
        needle = "UnifiedGraphOperationReport";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_unifying_view.rs" unifyingTest [
      {
        label = "unifying view gate";
        needle = "gate_unifying_view_validates_every_advanced_operation_on_one_graph";
      }
      {
        label = "mismatched evidence rejection";
        needle = "gate_unifying_view_rejects_mismatched_operation_evidence";
      }
      {
        label = "forged runtime rejection";
        needle = "forged-runtime-state";
      }
      {
        label = "forged save store-key rejection";
        needle = "forged-store-key";
      }
      {
        label = "forged search rejection";
        needle = "forged_search_failure";
      }
      {
        label = "non-search-produced failure rejection";
        needle = "search-failure-output";
      }
      {
        label = "forged fuzz rejection";
        needle = "forged_fuzz_iteration";
      }
      {
        label = "forged minimization rejection";
        needle = "forged_minimization";
      }
      {
        label = "typed evidence calls";
        needle = "UnifiedGraphOperationEvidence::";
      }
      {
        label = "same graph assertion";
        needle = "report.graph == graph_id";
      }
      {
        label = "unified validation calls";
        needle = "graph.validate_unified_operation";
      }
      {
        label = "resume covered";
        needle = "UnifiedGraphOperationKind::Resume";
      }
      {
        label = "fork covered";
        needle = "UnifiedGraphOperationKind::Fork";
      }
      {
        label = "save covered";
        needle = "UnifiedGraphOperationKind::Save";
      }
      {
        label = "replay covered";
        needle = "UnifiedGraphOperationKind::Replay";
      }
      {
        label = "search covered";
        needle = "UnifiedGraphOperationKind::StateSpaceSearch";
      }
      {
        label = "fuzz covered";
        needle = "UnifiedGraphOperationKind::CoverageGuidedFuzzing";
      }
      {
        label = "reproduction covered";
        needle = "UnifiedGraphOperationKind::ReproductionArtifact";
      }
      {
        label = "minimization covered";
        needle = "UnifiedGraphOperationKind::Minimization";
      }
      {
        label = "search failure path";
        needle = "search_with_strategy_and_failure_oracle";
      }
      {
        label = "fuzz path";
        needle = "fuzz_coverage_guided";
      }
      {
        label = "minimize path";
        needle = "MinimizationConfig::new";
      }
      {
        label = "real minimization assertion fold";
        needle = "OfflineAssertionChecker::new";
      }
      {
        label = "retained minimization log";
        needle = "RecordedAssertionLog::from_segments";
      }
      {
        label = "replay oracle report assertion";
        needle = "report.replay_oracle.thin_checkpoint";
      }
      {
        label = "single VM fingerprint assertion";
        needle = "report.single_vm_fingerprint.hash";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green unifying view gate";
        needle = "unifyingView = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-ADV-16\"]";
      }
      {
        label = "minimization raw dependency";
        needle = "phase6.minimization.rawGate";
      }
      {
        label = "single VM fingerprint raw dependency";
        needle = "phase2.gates.singleVmFingerprint.rawGate";
      }
      {
        label = "single VM fingerprint green dependency";
        needle = "dependencies = [\n        phase2.gates.singleVmFingerprint";
      }
      {
        label = "replay oracle raw dependency";
        needle = "phase4.gates.replayOracle.rawGate";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_unifying_view.rs" unifyingTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
      {
        label = "abstract spec engine";
        needle = "AbstractSpec";
      }
      {
        label = "second execution path";
        needle = "SecondExecutionPath";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 unifying-view check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-unifying-view";
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
          name = "run-unifying-view";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-unifying-view-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_unifying_view \
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
            gate=gate:unifying-view
            graph=single-temporal-graph
            instantiate=single-execution-model-entrypoint
            oracle=replay-oracle
            fingerprint=single-vm-fingerprint
            RESULT
          '';
        }
      ];
    }
