{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionViolationReproduction",
  taskIds ? ["T-ASRT-15"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  reproductionTest = builtins.readFile ../../crates/crucible/tests/assertion_violation_reproduction.rs;
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
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
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
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
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
    ++ failuresFor "crates/crucible/tests/assertion_violation_reproduction.rs" reproductionTest [
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
    ++ forbiddenFor "crates/crucible/tests/assertion_violation_reproduction.rs" reproductionTest [
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
    pkgs.mkDerivation {
      pname = "crucible-phase4-assertion-violation-reproduction";
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
          name = "run-assertion-violation-reproduction";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-assertion-violation-reproduction-target" \
              -p crucible \
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
