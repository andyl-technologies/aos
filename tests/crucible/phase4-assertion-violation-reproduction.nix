{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionViolationReproduction",
  taskIds ? ["T-ASRT-15"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/crucible-engine/src/lib.rs;
  reproductionTest = builtins.readFile ../../crates/crucible/crucible-engine/tests/assertion_violation_reproduction.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-15 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionViolationReproduction`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/trigger.rs" trigger [
      {
        label = "public replay checker";
        needle = "pub fn check_assertion_violation_reproduction";
      }
      {
        label = "oracle-aware replay checker";
        needle = "pub fn check_assertion_violation_reproduction_with_oracles";
      }
      {
        label = "replay report";
        needle = "pub struct AssertionViolationReplayReport";
      }
      {
        label = "artifact replay evidence";
        needle = "pub struct AssertionViolationArtifactReplay";
      }
      {
        label = "bisection request";
        needle = "pub struct AssertionViolationBisectionRequest";
      }
      {
        label = "localized divergence";
        needle = "pub struct AssertionViolationDivergence";
      }
      {
        label = "replay error";
        needle = "pub enum AssertionViolationReplayError";
      }
      {
        label = "artifact reduction replay";
        needle = "pub fn from_artifact";
      }
      {
        label = "artifact replay mismatch";
        needle = "ReplayArtifactMismatch";
      }
      {
        label = "offset-preserving replay check";
        needle = ".check_run_with_oracle(properties, recorded_log, oracle)";
      }
      {
        label = "oracle-preserving helper";
        needle = "assertion_replay_report_for_log_with_oracle";
      }
      {
        label = "artifact id rebound onto violations";
        needle = "host_assertion_report_with_reproduction_artifact";
      }
      {
        label = "prefix bisection";
        needle = "first_different_assertion_replay_prefix";
      }
      {
        label = "divergence error variant";
        needle = "AssertionViolationReplayError::Divergence";
      }
      {
        label = "missing recorded violation guard";
        needle = "MissingRecordedViolation";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/lib.rs" crateRoot [
      {
        label = "checker export";
        needle = "check_assertion_violation_reproduction";
      }
      {
        label = "oracle checker export";
        needle = "check_assertion_violation_reproduction_with_oracles";
      }
      {
        label = "divergence export";
        needle = "AssertionViolationDivergence";
      }
      {
        label = "artifact replay export";
        needle = "AssertionViolationArtifactReplay";
      }
      {
        label = "bisection export";
        needle = "AssertionViolationBisectionRequest";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/tests/assertion_violation_reproduction.rs" reproductionTest [
      {
        label = "successful reproduction test";
        needle = "violation_reproduction_replays_same_artifact_and_violation";
      }
      {
        label = "divergence reproduction test";
        needle = "violation_reproduction_localizes_non_reproduction_as_divergence";
      }
      {
        label = "missing violation test";
        needle = "violation_reproduction_rejects_logs_without_recorded_violation";
      }
      {
        label = "artifact schedule drift test";
        needle = "violation_reproduction_rejects_replay_from_different_artifact_schedule";
      }
      {
        label = "oracle offset replay test";
        needle = "violation_reproduction_with_oracles_preserves_recorded_offsets";
      }
      {
        label = "self-contained artifact capture";
        needle = "ReproductionArtifact::capture";
      }
      {
        label = "sealed artifact replay evidence";
        needle = "AssertionViolationArtifactReplay::from_artifact";
      }
      {
        label = "same artifact assertion";
        needle = "assert_eq!(violation.reproduction_artifact, artifact_id)";
      }
      {
        label = "divergence prefix assertion";
        needle = "assert_eq!(divergence.first_different_prefix_len, 4)";
      }
      {
        label = "bisection request assertion";
        needle = "assert_eq!(divergence.bisection.first_different_event_prefix_len, 4)";
      }
      {
        label = "divergence icount assertion";
        needle = "assert_eq!(divergence.first_different_icount, Some(icount(7)))";
      }
      {
        label = "observational diagnostic replay nonperturbation test";
        needle = "violation_reproduction_ignores_observational_diagnostic_replay_entries";
      }
      {
        label = "report-only divergence has no event";
        needle = "assert!(divergence.expected_event.is_none())";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion violation reproduction import";
        needle = "assertionViolationReproduction = import ./phase4-assertion-violation-reproduction.nix";
      }
      {
        label = "phase4 assertion violation reproduction attr path";
        needle = "attrPath = \"checks.crucible.phase4.assertionViolationReproduction\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/tests/assertion_violation_reproduction.rs" reproductionTest [
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
  then throw "crucible phase4 assertion-violation-reproduction check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase4-assertion-violation-reproduction";

      # The crucible crate links the campaign store's SQLite backend, so its
      # test binaries need SQLite at link time.
      buildDeps = [
        pkgs.sqlite
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-assertion-violation-reproduction";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-engine \
              --test assertion_violation_reproduction \
              --test assertion_violation_records \
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
            assertion_violation_reproduction=true
            RESULT
          '';
        }
      ];
    }
