{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.coverageFeedback",
  taskIds ? ["T-ADV-11"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  coverageFeedbackTest = builtins.readFile ../../crates/crucible/tests/gate_coverage_feedback.rs;
  eventLogCoverageGate = builtins.readFile ./phase4-event-log-coverage.nix;
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

  defaultCoverageFeedbackBlock =
    sliceFromUntil
    defaultChecks
    "    coverageFeedback = greenBeforeAdvance {"
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
        label = "T-ADV-11 completion note";
        needle = "Completed by `checks.crucible.phase6.coverageFeedback`";
      }
      {
        label = "ADV-22 coverage projection";
        needle = "Search and fuzzing read the **coverage projection** of\nthe log";
      }
      {
        label = "ADV-23 reduce invariant";
        needle = "recording or\n  reading coverage MUST be free of any effect on `reduce`";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-event-log-coverage.nix" eventLogCoverageGate [
      {
        label = "event-log coverage projection prerequisite";
        needle = "event_log_coverage_projection=true";
      }
      {
        label = "checkpoint coverage fingerprint prerequisite";
        needle = "checkpoint_coverage_fingerprint=projection-digest";
      }
    ]
    ++ failuresFor "tests/crucible/phase6-search-strategies.nix" searchStrategiesGate [
      {
        label = "coverage-guided strategy prerequisite";
        needle = "gate_coverage_guided_prefers_recorded_coverage_feedback";
      }
    ]
    ++ failuresFor "tests/crucible/phase6-basic-block-coverage.nix" basicBlockCoverageGate [
      {
        label = "basic-block coverage prerequisite";
        needle = "gate=gate:basic-block-coverage";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "coverage feedback consumer enum";
        needle = "pub enum EventLogCoverageFeedbackConsumer";
      }
      {
        label = "coverage feedback signal type";
        needle = "pub struct EventLogCoverageFeedback";
      }
      {
        label = "coverage feedback from event log";
        needle = "pub fn from_event_log(entries: &[SchedulerEventLogEntry]) -> Self";
      }
      {
        label = "coverage feedback consumer fingerprint";
        needle = "pub fn fingerprint_for(&self, consumer: EventLogCoverageFeedbackConsumer) -> ContentHash";
      }
      {
        label = "fuzzing feedback consumer";
        needle = "CoverageGuidedFuzzing";
      }
      {
        label = "coverage projection API";
        needle = "pub fn event_log_coverage_projection";
      }
      {
        label = "coverage fingerprint API";
        needle = "pub fn coverage_fingerprint_from_event_log";
      }
      {
        label = "projection feedback doc";
        needle = "Coverage projection used by search/fuzzing feedback and checkpoint fingerprints.";
      }
      {
        label = "coverage entries are unique feedback material";
        needle = ".collect::<BTreeSet<_>>()";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "checkpoint derives coverage from event log";
        needle = "pub fn with_coverage_from_event_log";
      }
      {
        label = "graph cache derives coverage from event log";
        needle = "pub fn cache_snapshot_with_event_log_coverage";
      }
      {
        label = "coverage-guided strategy";
        needle = "SearchStrategy::CoverageGuided";
      }
      {
        label = "coverage feedback reader";
        needle = "fn search_candidate_coverage_fingerprint";
      }
      {
        label = "search reads checkpoint coverage";
        needle = "checkpoint.coverage_fingerprint";
      }
      {
        label = "reduce signature";
        needle = "pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> Result<State, EngineError>";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "coverage feedback export";
        needle = "EventLogCoverageFeedback";
      }
      {
        label = "coverage feedback consumer export";
        needle = "EventLogCoverageFeedbackConsumer";
      }
      {
        label = "coverage projection export";
        needle = "event_log_coverage_projection";
      }
      {
        label = "coverage fingerprint export";
        needle = "coverage_fingerprint_from_event_log";
      }
      {
        label = "search strategy export";
        needle = "SearchStrategy";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_coverage_feedback.rs" coverageFeedbackTest [
      {
        label = "event log to search gate";
        needle = "gate_coverage_feedback_flows_from_event_log_projection_to_search";
      }
      {
        label = "reduce invariant gate";
        needle = "gate_coverage_feedback_never_affects_reduce";
      }
      {
        label = "event log coverage projection used";
        needle = "event_log_coverage_projection(&first_log)";
      }
      {
        label = "fuzzer-facing feedback signal";
        needle = "EventLogCoverageFeedback::from_event_log(&first_log)";
      }
      {
        label = "search feedback consumer assertion";
        needle = "EventLogCoverageFeedbackConsumer::Search";
      }
      {
        label = "fuzzing feedback consumer assertion";
        needle = "EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing";
      }
      {
        label = "checkpoint coverage from event log used";
        needle = "with_coverage_from_event_log";
      }
      {
        label = "graph cache coverage path used";
        needle = "cache_snapshot_with_event_log_coverage";
      }
      {
        label = "coverage-guided search used";
        needle = "SearchStrategy::CoverageGuided";
      }
      {
        label = "coverage fingerprint assertion";
        needle = "coverage_fingerprint_from_event_log(&first_log)";
      }
      {
        label = "reduce equality assertion";
        needle = "assert_eq!(reduced_before.id, reduced_after.id);";
      }
      {
        label = "causal determinism exclusion assertion";
        needle = "compare_event_log_determinism(&baseline, &with_coverage).passes()";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_coverage_feedback.rs" coverageFeedbackTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix coverageFeedback block" defaultCoverageFeedbackBlock [
      {
        label = "phase6 coverage feedback green wrapper";
        needle = "coverageFeedback = greenBeforeAdvance";
      }
      {
        label = "phase6 coverage feedback import";
        needle = "gate = import ./phase6-coverage-feedback.nix";
      }
      {
        label = "phase6 coverage feedback attr path";
        needle = "checks.crucible.phase6.coverageFeedback";
      }
      {
        label = "phase6 coverage feedback task id";
        needle = ''taskIds = ["T-ADV-11"]'';
      }
      {
        label = "phase2 single VM fingerprint raw dependency";
        needle = "\n          phase2.gates.singleVmFingerprint.rawGate\n";
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
        label = "phase4 event log coverage dependency";
        needle = "\n          phase4.eventLogCoverage\n";
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
        label = "phase2 single VM fingerprint green dependency";
        needle = "\n        phase2.gates.singleVmFingerprint\n";
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
        label = "phase4 event log coverage green dependency";
        needle = "\n        phase4.eventLogCoverage\n";
      }
      {
        label = "phase6 search strategies green dependency";
        needle = "\n        phase6.searchStrategies\n";
      }
      {
        label = "phase6 basic block coverage green dependency";
        needle = "\n        phase6.basicBlockCoverage\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 coverage feedback check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-coverage-feedback";
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
          name = "run-coverage-feedback";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-coverage-feedback-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_coverage_feedback \
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
            gate=gate:coverage-feedback
            event_log_projection=single-source
            search_feedback=checkpoint-coverage-fingerprint
            fuzzing_feedback=checkpoint-coverage-fingerprint
            reduce_effect=none
            RESULT
          '';
        }
      ];
    }
