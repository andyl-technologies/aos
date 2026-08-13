{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.coverageGuidedFuzzing",
  taskIds ? ["T-ADV-12"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  coverageGuidedFuzzingTest = builtins.readFile ../../crates/crucible/tests/gate_coverage_guided_fuzzing.rs;
  coverageFeedbackGate = builtins.readFile ./phase6-coverage-feedback.nix;
  searchStrategiesGate = builtins.readFile ./phase6-search-strategies.nix;
  basicBlockCoverageGate = builtins.readFile ./phase6-basic-block-coverage.nix;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  indexOf = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
    matches =
      builtins.filter (
        index: builtins.substring index needleLen haystack == needle
      )
      indexes;
  in
    if matches == []
    then null
    else builtins.head matches;

  sliceFromUntil = content: startNeedle: endNeedle: let
    start = indexOf startNeedle content;
    tailStart = start + builtins.stringLength startNeedle;
    tail = builtins.substring tailStart (builtins.stringLength content - tailStart) content;
    end = indexOf endNeedle tail;
  in
    if start == null
    then ""
    else if end == null
    then startNeedle + tail
    else startNeedle + builtins.substring 0 end tail;

  defaultCoverageGuidedFuzzingBlock =
    sliceFromUntil
    defaultChecks
    "    coverageGuidedFuzzing = greenBeforeAdvance {"
    "    gates = {";

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
        label = "T-ADV-12 completion note";
        needle = "Completed by `checks.crucible.phase6.coverageGuidedFuzzing`";
      }
      {
        label = "ADV-24 family fuzzing requirement";
        needle = "Fuzzing MUST be coverage-guided sampling/mutation of the schedule";
      }
      {
        label = "ADV-24 pinned scenario requirement";
        needle = "fuzzing MUST NOT execute a family directly";
      }
      {
        label = "ADV-25 deterministic choice requirement";
        needle = "Every fuzzer choice — corpus-entry selection, mutation, family\n  sampling, and energy assignment — MUST be a deterministic function of a recorded\n  seed";
      }
    ]
    ++ failuresFor "tests/crucible/phase6-coverage-feedback.nix" coverageFeedbackGate [
      {
        label = "fuzzing feedback prerequisite";
        needle = "fuzzing_feedback=checkpoint-coverage-fingerprint";
      }
      {
        label = "coverage feedback consumer prerequisite";
        needle = "EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing";
      }
    ]
    ++ failuresFor "tests/crucible/phase6-search-strategies.nix" searchStrategiesGate [
      {
        label = "coverage-guided search prerequisite";
        needle = "gate_coverage_guided_prefers_recorded_coverage_feedback";
      }
    ]
    ++ failuresFor "tests/crucible/phase6-basic-block-coverage.nix" basicBlockCoverageGate [
      {
        label = "basic-block coverage prerequisite";
        needle = "gate=gate:basic-block-coverage";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "fuzz config type";
        needle = "pub struct CoverageGuidedFuzzConfig";
      }
      {
        label = "fuzz run type";
        needle = "pub struct CoverageGuidedFuzzRun";
      }
      {
        label = "fuzz iteration type";
        needle = "pub struct CoverageGuidedFuzzIteration";
      }
      {
        label = "scenario family fuzzer API";
        needle = "pub fn fuzz_coverage_guided";
      }
      {
        label = "event-log feedback input";
        needle = "feedback: &[EventLogCoverageFeedback]";
      }
      {
        label = "coverage-guided fuzzing consumer";
        needle = "EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing";
      }
      {
        label = "seeded sampling helper";
        needle = "fn coverage_guided_fuzz_sample_index";
      }
      {
        label = "family sample pinning";
        needle = "family.instantiate_sample(sample_index)?";
      }
      {
        label = "schedule override mutation";
        needle = "Decision::Override(OverrideDecision";
      }
      {
        label = "corpus parent selection";
        needle = "selected_corpus_entry";
      }
      {
        label = "deterministic energy assignment";
        needle = "fn coverage_guided_fuzz_energy";
      }
      {
        label = "mutated configuration";
        needle = "try_step(root.configuration(), mutation.clone())?";
      }
      {
        label = "coverage-biased order";
        needle = "coverage_biased_order";
      }
      {
        label = "new coverage marker";
        needle = "new_coverage";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "fuzz config export";
        needle = "CoverageGuidedFuzzConfig";
      }
      {
        label = "fuzz iteration export";
        needle = "CoverageGuidedFuzzIteration";
      }
      {
        label = "fuzz run export";
        needle = "CoverageGuidedFuzzRun";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_coverage_guided_fuzzing.rs" coverageGuidedFuzzingTest [
      {
        label = "reproducible fuzzing gate";
        needle = "gate_coverage_guided_fuzzing_is_seeded_and_reproducible";
      }
      {
        label = "first-seen coverage gate";
        needle = "gate_coverage_guided_fuzzing_prefers_first_seen_coverage";
      }
      {
        label = "scenario family API used";
        needle = "ScenarioFamily::new";
      }
      {
        label = "fuzz config used";
        needle = "CoverageGuidedFuzzConfig::new";
      }
      {
        label = "fuzzer API used";
        needle = "fuzz_coverage_guided";
      }
      {
        label = "coverage feedback built from event log";
        needle = "EventLogCoverageFeedback::from_event_log(&log)";
      }
      {
        label = "fuzzing feedback consumer assertion";
        needle = "EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing";
      }
      {
        label = "schedule override assertion";
        needle = "matches!(iteration.mutation, Decision::Override(_))";
      }
      {
        label = "typed mutation variation assertion";
        needle = "unique_sample_indexes(&first)";
      }
      {
        label = "corpus parent assertion";
        needle = "selected_corpus_entry";
      }
      {
        label = "energy assertion";
        needle = "iteration.energy > 0";
      }
      {
        label = "reduce reproducibility assertion";
        needle = "reduce(&iteration.configuration.def, iteration.schedule()).is_ok()";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_coverage_guided_fuzzing.rs" coverageGuidedFuzzingTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix coverageGuidedFuzzing block" defaultCoverageGuidedFuzzingBlock [
      {
        label = "phase6 coverage-guided fuzzing green wrapper";
        needle = "coverageGuidedFuzzing = greenBeforeAdvance";
      }
      {
        label = "phase6 coverage-guided fuzzing import";
        needle = "gate = import ./phase6-coverage-guided-fuzzing.nix";
      }
      {
        label = "phase6 coverage-guided fuzzing attr path";
        needle = "checks.crucible.phase6.coverageGuidedFuzzing";
      }
      {
        label = "phase6 coverage-guided fuzzing task id";
        needle = ''taskIds = ["T-ADV-12"]'';
      }
      {
        label = "phase1 content address raw dependency";
        needle = "\n          phase1.gates.contentAddress.rawGate\n";
      }
      {
        label = "phase4 e2e determinism raw dependency";
        needle = "\n          phase4.gates.e2eDeterminism.rawGate\n";
      }
      {
        label = "phase4 replay oracle raw dependency";
        needle = "\n          phase4.gates.replayOracle.rawGate\n";
      }
      {
        label = "phase6 state-space search raw dependency";
        needle = "\n          phase6.stateSpaceSearch.rawGate\n";
      }
      {
        label = "phase6 search strategies raw dependency";
        needle = "\n          phase6.searchStrategies.rawGate\n";
      }
      {
        label = "phase6 basic block coverage raw dependency";
        needle = "\n          phase6.basicBlockCoverage.rawGate\n";
      }
      {
        label = "phase6 coverage feedback raw dependency";
        needle = "\n          phase6.coverageFeedback.rawGate\n";
      }
      {
        label = "phase6 guidance determinism lint raw dependency";
        needle = "\n          phase6.guidanceDeterminismLint.rawGate\n";
      }
      {
        label = "phase6 app-random branching raw dependency";
        needle = "\n          phase6.appRandomBranching.rawGate\n";
      }
      {
        label = "phase1 content address green dependency";
        needle = "\n        phase1.gates.contentAddress\n";
      }
      {
        label = "phase4 e2e determinism green dependency";
        needle = "\n        phase4.gates.e2eDeterminism\n";
      }
      {
        label = "phase4 replay oracle green dependency";
        needle = "\n        phase4.gates.replayOracle\n";
      }
      {
        label = "phase6 state-space search green dependency";
        needle = "\n        phase6.stateSpaceSearch\n";
      }
      {
        label = "phase6 search strategies green dependency";
        needle = "\n        phase6.searchStrategies\n";
      }
      {
        label = "phase6 basic block coverage green dependency";
        needle = "\n        phase6.basicBlockCoverage\n";
      }
      {
        label = "phase6 coverage feedback green dependency";
        needle = "\n        phase6.coverageFeedback\n";
      }
      {
        label = "phase6 guidance determinism lint green dependency";
        needle = "\n        phase6.guidanceDeterminismLint\n";
      }
      {
        label = "phase6 app-random branching green dependency";
        needle = "\n        phase6.appRandomBranching\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 coverage-guided fuzzing check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-coverage-guided-fuzzing";
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
          name = "run-coverage-guided-fuzzing";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-coverage-guided-fuzzing-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_coverage_guided_fuzzing \
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
            gate=gate:coverage-guided-fuzzing
            family_execution=pinned-scenario-only
            schedule_mutation=Decision::Override
            coverage_feedback=event-log-projection
            corpus_storage=deferred-to-T-ADV-13
            RESULT
          '';
        }
      ];
    }
