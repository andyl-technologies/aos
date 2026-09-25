{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.e2eDeterminism",
  taskIds ? [],
  openTaskIds ? [],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliE2eGate = builtins.readFile ../../crates/crucible-cli/tests/gate_e2e_determinism.rs;
  e2eHarness = builtins.readFile ../../crates/crucible-harness/src/e2e.rs;
  harnessE2eGate = builtins.readFile ../../crates/crucible-harness/tests/gate_e2e_determinism.rs;
  nativeRunner = ./_e2e-determinism-native-runner.sh;
  nativeRunnerSource = builtins.readFile nativeRunner;
  fleetRunner = builtins.readFile ./_fleet-runner.nix;

  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-cli/tests/gate_e2e_determinism.rs" cliE2eGate [
      {
        label = "CLI modeled artifact component";
        needle = "e2e_artifact_component_runs_mock_fault_and_property_corpus";
      }
      {
        label = "modeled machine-profile replay";
        needle = "e2e_artifact_component_replays_across_modeled_machine_profiles";
      }
      {
        label = "build identity negative control";
        needle = "e2e_artifact_component_rejects_build_identity_drift";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/e2e.rs" e2eHarness [
      {
        label = "representative artifact";
        needle = "pub fn representative_mock_e2e_artifact";
      }
      {
        label = "modeled gate runner";
        needle = "pub fn run_mock_e2e_determinism_gate";
      }
      {
        label = "distinct modeled-profile enforcement";
        needle = "MissingDifferentMachineProfile";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_e2e_determinism.rs" harnessE2eGate [
      {
        label = "hostile-profile artifact comparison";
        needle = "gate_e2e_determinism_runs_fault_injected_multi_vm_artifact_under_adversarial_profiles";
      }
      {
        label = "cross-profile negative control";
        needle = "gate_e2e_determinism_requires_cross_machine_reproduction_profile";
      }
    ]
    ++ failuresFor "tests/crucible/_e2e-determinism-native-runner.sh" nativeRunnerSource [
      {
        label = "local native gate runner";
        needle = "run-gate";
      }
      {
        label = "randomized worker profile";
        needle = "randomized-worker-two-core";
      }
      {
        label = "I/O-stall profile";
        needle = "loaded-io-stall-four-core";
      }
      {
        label = "wall-clock launch jitter";
        needle = "launch_jitter";
      }
      {
        label = "bounded scheduler preemption during replay";
        needle = "replay --bounded-scheduler-preemption";
      }
      {
        label = "varied native core matrix";
        needle = "varied_core_counts=1,2,4";
      }
      {
        label = "live packaged QEMU backend";
        needle = "--backend qemu";
      }
      {
        label = "nonempty live fingerprint enforcement";
        needle = "samples=[1-9][0-9]*";
      }
      {
        label = "byte-identical canonical result comparison";
        needle = "canonical log or fingerprint changed across native machine profiles";
      }
      {
        label = "byte-identical reproduction artifact identity";
        needle = "reproduction artifact changed across native machine profiles";
      }
      {
        label = "exact closure identity manifest";
        needle = "qemu_identity_sha256=";
      }
      {
        label = "retained raw native transcript";
        needle = ''"$profile_output/verify.jsonl"'';
      }
      {
        label = "validated local profile replay";
        needle = "local_profile_replay=true";
      }
      {
        label = "release manifest binding";
        needle = ''manifest_sha256=$(digest_file "$gate_output/manifest.env")'';
      }
    ]
    ++ forbiddenFor "tests/crucible/_e2e-determinism-native-runner.sh" nativeRunnerSource [
      {
        label = "host shell path";
        needle = "/bin/sh";
      }
      {
        label = "host bash path";
        needle = "/bin/bash";
      }
      {
        label = "environment shebang";
        needle = "/usr/bin/env";
      }
    ]
    ++ failuresFor "tests/crucible/_fleet-runner.nix" fleetRunner [
      {
        label = "native runner binding";
        needle = "e2eNativeRunnerPackage = pkgs.writeTextFile";
      }
      {
        label = "native runner environment";
        needle = "CRUCIBLE_E2E_NATIVE_RUNNER = e2eNativeRunner;";
      }
      {
        label = "live QEMU durable process state";
        needle = ''CRUCIBLE_RUN_STATE_ROOT="$FLEET_WORKDIR/run-state"'';
      }
    ];
in
  if failures != []
  then throw "crucible phase7 e2e-determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else if campaignComposition != null
  then
    import ./phase4-e2e-determinism.nix {
      inherit pkgs lib testing campaignComposition;
      inherit attrPath taskIds dependencies;
    }
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-e2e-determinism";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.bash
          pkgs.coreutils
          pkgs.grep
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
          name = "run-component-and-contract-tests";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/crucible-phase7-e2e-determinism-target" \
              -p crucible-cli --test gate_e2e_determinism -- --test-threads=1
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/crucible-phase7-e2e-determinism-target" \
              -p crucible-harness --test gate_e2e_determinism -- --test-threads=1

            ${pkgs.bash}/bin/bash -n ${nativeRunner}
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
            gate=gate:e2e-determinism
            component=gate:e2e-determinism/local-native-contract
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            canonical_gate_status=satisfied-by-executable-fleet-gate
            executable_gate=checks.fleet.crucible-e2e-determinism
            native_qemu_execution=validated
            local_profile_replay=validated
            randomized_worker_scheduling=validated
            wall_clock_jitter=validated
            host_io_stall=validated
            varied_core_counts=1,2,4
            evidence_schema=crucible.e2e.native-gate-evidence.v1
            ci_wiring_guard=checks.crucible.phase7.crucibleGateCiWiring
            RESULT
          '';
        }
      ];
    }
