{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.machineIndependentReproduction",
  taskIds ? ["T-HARN-25"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  reproduction = builtins.readFile ../../crates/crucible-harness/src/reproduction.rs;
  reproductionTest = builtins.readFile ../../crates/crucible-harness/tests/reproduction_artifact.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  e2ePhase7 = builtins.readFile ./phase7-e2e-determinism.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-25 checklist complete";
        needle = "- [x] **T-HARN-25**";
      }
      {
        label = "T-HARN-25 completion note";
        needle = "Completed by `checks.crucible.phase7.machineIndependentReproduction`";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "stale T-HARN-25 placeholder";
        needle = "- [ ] **T-HARN-25**";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/reproduction.rs" reproduction [
      {
        label = "producer canonical log evidence";
        needle = "PRODUCER_CANONICAL_LOG_COMPONENT_NAME";
      }
      {
        label = "producer final fingerprint evidence";
        needle = "PRODUCER_FINAL_FINGERPRINT_COMPONENT_NAME";
      }
      {
        label = "producer artifact digest evidence";
        needle = "PRODUCER_ARTIFACT_DIGEST_COMPONENT_NAME";
      }
      {
        label = "producer backend build id evidence";
        needle = "PRODUCER_BACKEND_BUILD_ID_COMPONENT_NAME";
      }
      {
        label = "recorded decision payload evidence";
        needle = "RECORDED_DECISION_PAYLOAD_MEDIA_TYPE";
      }
      {
        label = "machine reproduction report";
        needle = "pub struct MachineReproductionReport";
      }
      {
        label = "machine reproduction run";
        needle = "pub struct MachineReproductionRun";
      }
      {
        label = "mock expected identity";
        needle = "pub fn mock_reproduction_build_identity";
      }
      {
        label = "machine verification API";
        needle = "pub fn verify_mock_machine_independent_reproduction";
      }
      {
        label = "machine verification bytes API";
        needle = "pub fn verify_mock_machine_independent_reproduction_bytes";
      }
      {
        label = "profile replay API";
        needle = "pub fn reproduce_mock_reproduction_artifact_on_profile";
      }
      {
        label = "host adversary execution";
        needle = "run_profiled_producer_consumer_tasks";
      }
      {
        label = "identity mismatch error";
        needle = "BuildIdentityMismatch";
      }
      {
        label = "missing different machine profile error";
        needle = "MissingDifferentMachineProfile";
      }
      {
        label = "producer evidence mismatch error";
        needle = "MissingProducerEvidence";
      }
      {
        label = "producer artifact digest mismatch error";
        needle = "ProducerArtifactDigestMismatch";
      }
      {
        label = "machine mismatch error";
        needle = "MachineReproductionMismatch";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/reproduction_artifact.rs" reproductionTest [
      {
        label = "byte-identical host profile positive test";
        needle = "reproduction_artifact_machine_verification_replays_identically_across_host_profiles";
      }
      {
        label = "identity mismatch negative test";
        needle = "reproduction_artifact_machine_verification_rejects_build_identity_drift";
      }
      {
        label = "producer evidence mismatch negative test";
        needle = "reproduction_artifact_machine_verification_rejects_producer_evidence_mismatch";
      }
      {
        label = "scenario payload drift negative test";
        needle = "reproduction_artifact_machine_verification_rejects_scenario_payload_drift";
      }
      {
        label = "backend build id drift negative test";
        needle = "reproduction_artifact_machine_verification_rejects_backend_build_id_drift";
      }
      {
        label = "different machine profile negative test";
        needle = "reproduction_artifact_machine_verification_requires_different_machine_profile";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "replayable artifact validation";
        needle = "fn validate_replayable_reproduction_artifact";
      }
      {
        label = "expected replay identity";
        needle = "fn expected_replay_identity";
      }
      {
        # Drift: the selected QEMU file identity no longer comes from hashing
        # the binary on disk (`content_address_file`); it is read from the
        # artifact's embedded build marker and content-addressed from there,
        # which is what makes the identity machine-independent.
        label = "selected QEMU file identity";
        needle = "fn read_qemu_build_marker";
      }
      {
        label = "identity exit error";
        needle = "CliError::Identity";
      }
      {
        label = "identity exit code";
        needle = "Self::Identity(_) => 3";
      }
      {
        label = "CLI identity mismatch test";
        needle = "cli_replay_rejects_build_identity_mismatch_with_identity_exit";
      }
      {
        label = "CLI selected QEMU identity mismatch test";
        needle = "cli_replay_rejects_selected_qemu_file_identity_mismatch_with_identity_exit";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 machine reproduction check";
        needle = "machineIndependentReproduction = import ./phase7-machine-independent-reproduction.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-e2e-determinism.nix" e2ePhase7 [
      {
        label = "machine reproduction metadata";
        needle = "machine_independent_reproduction=checks.crucible.phase7.machineIndependentReproduction";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 machine-independent reproduction check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-machine-independent-reproduction";
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
          name = "run-machine-independent-reproduction";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-machine-independent-reproduction-target" \
              -p crucible-harness \
              --test reproduction_artifact \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-machine-independent-reproduction-target" \
              -p crucible-cli \
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
            owner=crucible-harness
            phase=phase7
            artifact=versioned-seed-scenario-schedule
            producer_evidence=canonical-log-and-final-fingerprint
            machine_independent_reproduction=producer-evidence-byte-identical-across-host-profiles
            identity_mismatch_exit=3
            shared_artifact_format=checks.crucible.phase7.reproductionArtifactFormat
            real_aos_fleet_reproduction=deferred-to-packaging-and-fleet-gates
            RESULT
          '';
        }
      ];
    }
