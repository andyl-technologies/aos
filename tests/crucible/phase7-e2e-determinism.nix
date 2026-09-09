{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.e2eDeterminism",
  taskIds ? [],
  openTaskIds ? ["T-HARN-23"],
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
  fleetRunner = builtins.readFile ./_fleet-runner.nix;
  rootDefault = builtins.readFile ../../default.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-23 open acceptance evidence";
        needle = "T-HARN-23 remains open";
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
        label = "CLI modeled artifact component test";
        needle = "e2e_artifact_component_runs_mock_fault_and_property_corpus";
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
        label = "modeled profile artifact replay";
        needle = "e2e_artifact_component_replays_across_modeled_machine_profiles";
      }
      {
        label = "build identity negative control";
        needle = "e2e_artifact_component_rejects_build_identity_drift";
      }
      {
        label = "distinct modeled profile negative control";
        needle = "e2e_artifact_component_requires_distinct_modeled_machine_profiles";
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
        label = "modeled-profile replay API";
        needle = "pub fn reproduce_mock_e2e_artifact_on_profile";
      }
      {
        label = "distinct modeled-profile enforcement";
        needle = "MissingDifferentMachineProfile";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_e2e_determinism.rs" harnessE2eGate [
      {
        label = "harness positive coverage";
        needle = "gate_e2e_determinism_runs_fault_injected_multi_vm_artifact_under_adversarial_profiles";
      }
      {
        label = "harness modeled-profile negative control";
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
        label = "phase4 check records modeled component scope";
        needle = "component=gate:e2e-determinism/scheduler-and-assertion-model";
      }
    ]
    ++ failuresFor "tests/crucible/_fleet-runner.nix" fleetRunner [
      {
        label = "live QEMU durable process state root";
        needle = ''CRUCIBLE_RUN_STATE_ROOT="$FLEET_WORKDIR/run-state"'';
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "packaged QEMU verifier";
        needle = ''--backend qemu'';
      }
      {
        label = "native slice identifies the exact modeled component";
        needle = "source_component=checks.crucible.phase7.gates.e2eDeterminism.rawGate";
      }
      {
        label = "positive live fingerprint samples";
        needle = ''grep -c 'samples=[1-9][0-9]*')'';
      }
      {
        label = "bit-identical live fingerprint streams";
        needle = ''distinct_fingerprints="$('';
      }
      {
        label = "native artifact replay uses bounded host preemption";
        needle = "CRUCIBLE_REPLAY_BOUNDED_SCHEDULER_PREEMPTION=1";
      }
      {
        label = "native slice retains the built-in corpus";
        needle = "scenario_corpus=happy-path.scn,partition-recovery.scn,crash-restart.scn,fault-campaign.fam,e2e-determinism.scenario.toml";
      }
      {
        label = "native slice records the required different machine profile";
        needle = "different_machine_profile_reproduction=true";
      }
      {
        label = "native slice records its physical-host scope";
        needle = "physical_cross_host_reproduction=false";
      }
      {
        label = "native slice records completed profile replay evidence";
        needle = "completed_requirements=HARN-23";
      }
      {
        label = "native slice keeps the real HARN-22 host-matrix gap explicit";
        needle = "missing_evidence=representative-native-randomized-worker-wall-clock-io-stall-varied-core-matrix";
      }
      {
        label = "distributed exploration reports its narrow component status";
        needle = "component=distributed-continuous-exploration-surface";
      }
      {
        label = "distributed exploration propagates the canonical e2e blocker";
        needle = "canonical_gate_blocked_by=gate:e2e-determinism";
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
            component=gate:e2e-determinism/mock-artifact-validation
            canonical_gate=gate:e2e-determinism
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            canonical_gate_status=unmet
            owner=crucible-cli
            phase=phase7
            scenario=shared-mock-multi-node-fault-injected-artifact
            artifact=mock-seed-scenario-schedule-build-identity
            modeled_adversarial_profiles=canonical-host-adversary-matrix
            modeled_profile_reproduction=true
            native_qemu_execution=false
            cross_machine_reproduction=false
            shared_artifact_format=checks.crucible.phase7.reproductionArtifactFormat
            machine_independent_reproduction=checks.crucible.phase7.machineIndependentReproduction
            native_reduction_slice=checks.fleet.crucible-e2e-determinism
            ci_wiring_guard=checks.crucible.phase7.crucibleGateCiWiring
            cli_component=implemented_shared_mock_artifact
            missing_evidence=artifact-replay-on-different-machine-profile
            RESULT
          '';
        }
      ];
    }
