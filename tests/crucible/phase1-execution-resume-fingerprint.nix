{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionResumeFingerprint",
  taskIds ? ["T-EXEC-5"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  decision = builtins.readFile ../../crates/crucible/crucible-engine/src/decision.rs;
  model = import ./_crucible-model-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible/crucible-engine/src/lib.rs" crateRoot [
      {
        label = "resume+continue fingerprint test";
        needle = "resume_continue_matches_uninterrupted_run_by_fingerprint";
      }
      {
        label = "uninterrupted recorder binding";
        needle = "let mut uninterrupted";
      }
      {
        label = "uninterrupted recorder constructor";
        needle = "DecisionRecorder::new(Configuration::genesis(scenario.clone()))";
      }
      {
        label = "resume from prefix configuration";
        needle = "let mut resumed = DecisionRecorder::new(prefix.clone());";
      }
      {
        label = "continuation starts after prefix";
        needle = "for index in 4..8";
      }
      {
        label = "prefix equivalence assertion";
        needle = "uninterrupted.schedule.prefix(prefix_len)";
      }
      {
        label = "prefix fingerprint differs from final";
        needle = "configuration_execution_fingerprint(&prefix)";
      }
      {
        label = "final configuration equality";
        needle = "assert_eq!(uninterrupted, resumed);";
      }
      {
        label = "final fingerprint equality";
        needle = "configuration_execution_fingerprint(&resumed)";
      }
      {
        label = "representative decision driver";
        needle = "pub(in crate::tests) fn record_representative_decision(";
      }
      {
        label = "pure fingerprint helper";
        needle = "pub(in crate::tests) fn configuration_execution_fingerprint(";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/decision.rs" decision [
      {
        label = "schedule hydration for resume";
        needle = "hydrate_streams(&rng, configuration.schedule.decisions())";
      }
      {
        label = "hydrate only recorded RNG draws";
        needle = "if let Decision::RngDraw(RngDecision { stream, .. }) = decision";
      }
      {
        label = "stream position advance";
        needle = "let _ = decision_stream.next_u64();";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/model.rs" model [
      {
        label = "pure reducer";
        needle = "pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> Result<State, EngineError>";
      }
      {
        label = "reducer hashes schedule";
        needle = "id: canonical::reduced_state_hash(def, schedule)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes resume fingerprint check";
        needle = "executionResumeFingerprint = import ./phase1-execution-resume-fingerprint.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution resume fingerprint check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-execution-resume-fingerprint";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
        pkgs.sqlite
      ];

      phases = [
        {
          name = "run-execution-resume-fingerprint";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-engine \
              --lib \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            proof=resume-plus-continue-equals-uninterrupted
            witness=reduced-state-execution-fingerprint
            rng_state=schedule-hydrated-decision-recorder
            RESULT
          '';
        }
      ];
    }
