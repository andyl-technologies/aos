{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.e2eDeterminism",
  taskIds ? ["T-HARN-23"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  cliE2eGate = builtins.readFile ../../crates/crucible-cli/tests/gate_e2e_determinism.rs;
  e2eHarness = builtins.readFile ../../crates/crucible-harness/src/e2e.rs;
  harnessE2eGate = builtins.readFile ../../crates/crucible-harness/tests/gate_e2e_determinism.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  defaultChecks = builtins.readFile ./default.nix;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  phase4E2e = builtins.readFile ./phase4-e2e-determinism.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-23 production fleet evidence";
        needle = "Production closure evidence is provided by `checks.fleet.crucible-e2e-determinism`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "CLI test dependency on shared harness";
        needle = "crucible-harness = { path = \"../crucible-harness\" }";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/gate_e2e_determinism.rs" cliE2eGate [
      {
        label = "CLI final acceptance artifact test";
        needle = "gate_e2e_determinism_cli_target_runs_final_acceptance_artifact";
      }
      {
        label = "fault class coverage";
        needle = "E2eFaultKind::Partition";
      }
      {
        label = "property class coverage";
        needle = "E2ePropertyKind::Eventually";
      }
      {
        label = "adversarial matrix";
        needle = "canonical_host_adversary_matrix()";
      }
      {
        label = "cross-machine artifact replay";
        needle = "gate_e2e_determinism_cli_target_replays_from_artifact_on_different_machine_profile";
      }
      {
        label = "build identity negative control";
        needle = "gate_e2e_determinism_cli_target_rejects_build_identity_drift";
      }
      {
        label = "different machine profile negative control";
        needle = "gate_e2e_determinism_cli_target_requires_cross_machine_reproduction";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/tests/gate_e2e_determinism.rs" cliE2eGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/e2e.rs" e2eHarness [
      {
        label = "representative artifact";
        needle = "pub fn representative_mock_e2e_artifact";
      }
      {
        label = "e2e gate runner";
        needle = "pub fn run_mock_e2e_determinism_gate";
      }
      {
        label = "cross-machine profile replay API";
        needle = "pub fn reproduce_mock_e2e_artifact_on_profile";
      }
      {
        label = "different machine profile enforcement";
        needle = "MissingDifferentMachineProfile";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_e2e_determinism.rs" harnessE2eGate [
      {
        label = "harness positive coverage";
        needle = "gate_e2e_determinism_runs_fault_injected_multi_vm_artifact_under_adversarial_profiles";
      }
      {
        label = "harness cross-machine negative control";
        needle = "gate_e2e_determinism_requires_cross_machine_reproduction_profile";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented CLI e2e gate target";
        needle = "gate: \"gate:e2e-determinism\",\n        package: \"crucible-cli\",\n        test_target: \"gate_e2e_determinism\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 e2e gate imported";
        needle = "gate = import ./phase7-e2e-determinism.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented CLI e2e target in mapping lint";
        needle = "gate = \"gate:e2e-determinism\";\n      package = \"crucible-cli\";\n      testTarget = \"gate_e2e_determinism\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
      {
        label = "remaining placeholder count";
        needle = "placeholder_targets=0";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-e2e-determinism.nix" phase4E2e [
      {
        label = "phase4 check records implemented CLI target";
        needle = "final_acceptance_cli_target=implemented_shared_mock_artifact";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 e2e-determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-e2e-determinism";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

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
          name = "run-e2e-determinism";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-e2e-determinism-target" \
              -p crucible-cli \
              --test gate_e2e_determinism \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-e2e-determinism-target" \
              -p crucible-harness \
              --test gate_e2e_determinism \
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
            gate=gate:e2e-determinism
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            status=complete
            owner=crucible-cli
            phase=phase7
            scenario=shared-mock-multi-node-fault-injected-artifact
            artifact=mock-seed-scenario-schedule-build-identity
            adversarial_profiles=canonical-host-adversary-matrix
            cross_machine_reproduction=different-machine-profile-replay
            shared_artifact_format=checks.crucible.phase7.reproductionArtifactFormat
            machine_independent_reproduction=checks.crucible.phase7.machineIndependentReproduction
            real_host_reproduction=checks.fleet.crucible-e2e-determinism
            ci_check_class=fleet-check-surface
            fleet_check_surface=checks.fleet.crucible-e2e-determinism
            ci_wiring_guard=checks.crucible.phase7.crucibleGateCiWiring
            cli_target=implemented_shared_mock_artifact
            RESULT
          '';
        }
      ];
    }
