{
  pkgs,
  lib,
  testing,
  compositions,
}: let
  inventory = builtins.fromTOML (builtins.readFile ./campaign-gate-matrix-inventory.toml);
  expectedGateNames = map (authority: authority.gate) inventory.authorities;

  mkAdapters = composition: let
    inherit (composition) mode system;
    campaignComposition = {inherit mode system;};
    native = path:
      import path {
        inherit pkgs lib testing mode system;
      };
    productionGate = import ./phase7-production-rust-plugin-flight.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.productionRustPluginFlight";
    };
    productionFlight = import ./phase9-campaign-mode-production-rust-plugin-flight.nix {
      inherit pkgs lib testing mode system productionGate;
    };
    divergenceBisect = native ./phase9-campaign-mode-native-divergence-bisect.nix;
    replayOracle = native ./phase9-campaign-mode-replay-oracle.nix;
    deviceWorkOverlap = import ./phase7-device-host-work-overlap.nix {
      inherit pkgs lib testing campaignComposition;
    };
    fingerprintDigestOffload = import ./phase7-fingerprint-digest-offload.nix {
      inherit pkgs lib testing campaignComposition;
      productionPluginFlight = productionFlight;
    };
    hostParallelism = import ./phase7-qemu-host-parallel.nix {
      inherit pkgs lib testing campaignComposition;
      productionPluginFlight = productionFlight;
    };
    restoreLatency = import ./phase2-qemu-checkpoint-delta-flight.nix {
      inherit pkgs lib testing campaignComposition;
    };
    segmentReplay = import ./phase7-segment-parallel-replay.nix {
      inherit pkgs lib testing campaignComposition;
      dependencies = [divergenceBisect replayOracle];
    };
    translationPrefetchNeutrality = import ./phase7-translation-prefetch-neutrality.nix {
      inherit pkgs lib testing campaignComposition;
      productionPluginFlight = productionFlight;
    };
    e2eDeterminism = import ./phase7-e2e-determinism.nix {
      inherit pkgs lib testing campaignComposition;
      attrPath = "checks.crucible.phase7.gates.e2eDeterminism";
      taskIds = [];
      openTaskIds = [];
      dependencies = [];
    };
    fleetEquivalence = import ./phase7-crucible-fleet-equivalence.nix {
      inherit pkgs lib testing campaignComposition e2eDeterminism;
      attrPath = "checks.crucible.phase7.gates.fleetEquivalence";
      taskIds = ["T-DCE-8"];
      dependencies = [];
    };
  in {
    "gate:harness-lint" = import ./phase9-campaign-mode-static-closure.nix {
      inherit pkgs lib mode system;
      gatePath = ./phase1-harness-lint.nix;
      gateName = "gate:harness-lint";
      authoritativeAttr = "checks.crucible.phase1.gates.harnessLint";
    };
    "gate:layer0-determinism" = native ./phase9-campaign-mode-native-layer0-determinism.nix;
    "gate:content-address" = native ./phase9-campaign-mode-native-content-address.nix;
    "gate:campaign-model" = native ./phase9-campaign-mode-campaign-model.nix;
    "gate:campaign-statistics" = native ./phase9-campaign-mode-native-campaign-statistics.nix;
    "gate:single-vm-fingerprint" = import ./phase1-production-fingerprint-sample.nix {
      inherit pkgs lib campaignComposition;
      attrPath = "checks.crucible.phase2.gates.singleVmFingerprint";
    };
    "gate:scheduler-liveness" = native ./phase9-campaign-mode-native-scheduler-liveness.nix;
    "gate:adversarial-determinism" = native ./phase9-campaign-mode-native-adversarial-determinism.nix;
    "gate:e2e-determinism" = e2eDeterminism;
    "gate:control-responsive" = native ./phase9-campaign-mode-native-control-responsive.nix;
    "gate:basic-block-coverage" = native ./phase9-campaign-mode-basic-block-coverage.nix;
    "gate:checkpoint-materialization" = native ./phase9-campaign-mode-checkpoint-materialization.nix;
    "gate:state-space-search" = native ./phase9-campaign-mode-native-state-space-search.nix;
    "gate:perf-bench" = import ./phase7-perf-bench.nix {
      inherit
        pkgs
        lib
        testing
        campaignComposition
        deviceWorkOverlap
        fingerprintDigestOffload
        hostParallelism
        restoreLatency
        segmentReplay
        translationPrefetchNeutrality
        ;
    };
    "gate:fleet-equivalence" = fleetEquivalence;
    "gate:campaign-continuity" = native ./phase9-campaign-mode-native-campaign-continuity.nix;
    "gate:replay-oracle" = replayOracle;
    "gate:divergence-bisect" = divergenceBisect;
    "gate:layer1-injection" = import ./phase1-layer1-injection.nix {
      inherit pkgs lib testing campaignComposition;
      attrPath = "checks.crucible.phase3.gates.layer1Injection";
    };
    "gate:signal-fault-system" = native ./phase9-campaign-mode-signal-fault-system.nix;
    "gate:abi-conformance" = import ./phase9-campaign-mode-static-closure.nix {
      inherit pkgs lib mode system;
      gatePath = ./phase2-abi-conformance.nix;
      gateName = "gate:abi-conformance";
      authoritativeAttr = "checks.crucible.phase2.gates.abiConformance";
    };
    "gate:typed-choice" = native ./phase9-campaign-mode-native-typed-choice.nix;
    "gate:patch-microtests" = import ./phase2-patch-microtests.nix {
      inherit pkgs lib testing campaignComposition;
    };
    "gate:production-rust-plugin-flight" = productionFlight;
    "gate:qemu-inert" = import ./phase2-qemu-inert.nix {
      inherit pkgs lib testing campaignComposition;
    };
    "gate:any-guest" = import ./phase2-any-guest.nix {
      inherit pkgs lib testing campaignComposition;
    };
    "gate:license-boundary" = import ./phase9-campaign-mode-license-boundary.nix {
      inherit pkgs lib mode system;
    };
  };

  disabled = mkAdapters compositions.disabled;
  enabled = mkAdapters compositions.enabled;
  actualGateNames = builtins.attrNames disabled;
  enabledGateNames = builtins.attrNames enabled;
  missingGateNames = builtins.filter (gate: !(builtins.hasAttr gate disabled)) expectedGateNames;
  extraGateNames = builtins.filter (gate: !(builtins.elem gate expectedGateNames)) actualGateNames;
  adapterPaths =
    lib.concatMap (gate: [
      (toString disabled.${gate})
      (toString enabled.${gate})
    ])
    actualGateNames;
  failures =
    map (gate: "${gate}: missing authoritative adapter") missingGateNames
    ++ map (gate: "${gate}: unexpected authoritative adapter") extraGateNames
    ++ lib.optional (actualGateNames != enabledGateNames) "enabled and disabled adapter gate sets differ"
    ++ lib.optional (
      builtins.length actualGateNames != builtins.length expectedGateNames
    ) "adapter gate count differs from the authoritative inventory"
    ++ lib.optional (
      builtins.length adapterPaths != builtins.length (lib.unique adapterPaths)
    ) "two gate/mode rows alias one adapter derivation";
in
  if failures != []
  then throw "crucible campaign mode adapter map is incomplete:\n${builtins.concatStringsSep "\n" failures}"
  else
    builtins.listToAttrs (
      map (gate: {
        name = gate;
        value = {
          disabled = disabled.${gate};
          enabled = enabled.${gate};
        };
      })
      expectedGateNames
    )
