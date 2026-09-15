{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.e2eDeterminism",
  taskIds ? ["T-ASRT-16" "T-DET-26" "T-HARN-23"],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  fleetRunner = import ./_fleet-runner.nix {inherit pkgs lib testing;};
  nginxCurlGuest = import ./_nginx-curl-http-200-guest.nix {inherit pkgs;};
  representativeScenarioPackage = pkgs.writeTextFile {
    name = "crucible-e2e-determinism-scenario";
    text = builtins.readFile ./fixtures/e2e-determinism.scenario.toml;
    destination = "/share/crucible/e2e-determinism.scenario.toml";
  };
  representativeScenario = "${representativeScenarioPackage}/share/crucible/e2e-determinism.scenario.toml";
  nativeRunner = fleetRunner.e2eNativeRunner;

  harnessLib = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  nativeRunnerSource = builtins.readFile ./_e2e-determinism-native-runner.sh;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  assertionsDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-26 native acceptance completion";
        needle = "Completed by `checks.crucible.phase4.gates.e2eDeterminism.rawGate`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionsDoc [
      {
        label = "T-ASRT-16 completion note";
        needle = "Completed by `checks.crucible.phase4.gates.e2eDeterminism` and";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-23 native acceptance completion";
        needle = "Completed by `checks.crucible.phase4.gates.e2eDeterminism.rawGate`";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" harnessLib [
      {
        label = "implemented canonical e2e gate";
        needle = "name: \"gate:e2e-determinism\",\n        phase: GatePhase::Phase4,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "tests/crucible/_e2e-determinism-native-runner.sh" nativeRunnerSource [
      {
        label = "native executable gate entry point";
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
        label = "varied core counts";
        needle = "varied_core_counts=1,2,4";
      }
      {
        label = "live packaged QEMU backend";
        needle = "--backend qemu";
      }
      {
        label = "live fingerprint evidence";
        needle = "samples=[1-9][0-9]*";
      }
      {
        label = "canonical identity comparison";
        needle = "canonical-identities.tsv";
      }
      {
        label = "artifact identity comparison";
        needle = "reproduction-artifacts.sha256";
      }
      {
        label = "different-profile replay";
        needle = "quiet-to-loaded-four-core";
      }
      {
        label = "retained raw native transcript";
        needle = ''"$profile_output/verify.jsonl"'';
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
    ];
in
  if failures != []
  then throw "crucible phase4 e2e-determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    fleetRunner.mkCrucibleFleetCheck {
      name = "crucible-e2e-determinism";
      checkPath = attrPath;
      gateResults = dependencies;
      extraClosure = [nginxCurlGuest representativeScenarioPackage];
      inherit campaignComposition;
      gateName = "gate:e2e-determinism";
      authoritativeAttr = attrPath;
      runPhaseScript = ''
        set -eu

        scenario_materializer="$CRUCIBLE/bin/crucible-e2e-determinism-scenario"
        test -x "$scenario_materializer"
        "$scenario_materializer" --emit-scenario > "$FLEET_WORKDIR/e2e-determinism.scenario.toml"
        cmp ${representativeScenario} "$FLEET_WORKDIR/e2e-determinism.scenario.toml"

        export CRUCIBLE_E2E_ROOT_IMAGE=${nginxCurlGuest}/root.ext4
        export CRUCIBLE_E2E_KERNEL_CMDLINE='console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init'
        export CRUCIBLE_E2E_SCENARIO=${representativeScenario}
        export CRUCIBLE_E2E_SEED=0xe2e

        native_evidence="$FLEET_WORKDIR/native-gate-evidence"
        ${pkgs.bash}/bin/bash ${nativeRunner} run-gate "$native_evidence"
        grep -q '^PASS$' "$native_evidence/result"
        grep -q '^native_qemu_execution=true$' "$native_evidence/result"
        grep -q '^artifact_replay=different-machine-profile-byte-identical$' \
          "$native_evidence/result"

        mkdir -p "$out/evidence"
        cp -R "$native_evidence"/. "$out/evidence"/
      '';
      resultLines = [
        "gate=gate:e2e-determinism"
        "component=gate:e2e-determinism/native-qemu-acceptance"
        "canonical_gate=gate:e2e-determinism"
        "canonical_gate_status=satisfied"
        "tasks=${builtins.concatStringsSep "," taskIds}"
        "backend=qemu-tcg-production-vm-lifecycle"
        "scenario=representative-three-vm-fault-injected"
        "native_workload=nginx-curl-block-ninep"
        "faults=partition,loss,latency,crash"
        "properties=always,eventually,sometimes"
        "native_qemu_execution=true"
        "live_event_streams=bit-identical"
        "live_execution_fingerprint_streams=bit-identical-nonempty"
        "host_profiles=quiet-single-core,randomized-worker-two-core,loaded-io-stall-four-core"
        "randomized_worker_scheduling=true"
        "wall_clock_jitter=true"
        "host_io_stall=true"
        "varied_core_counts=1,2,4"
        "artifact_replay=true"
        "artifact_replay_source_profile=quiet-single-core"
        "artifact_replay_target_profile=loaded-io-stall-four-core"
        "artifact_replay_identity=canonical-event-and-fingerprint-streams-byte-identical"
        "retained_evidence=$out/evidence"
        "retained_diagnostics=profile-jsonl,profile-manifests,pressure-status,canonical-identities,artifact-digests,replay-jsonl,identity-manifest"
      ];
    }
