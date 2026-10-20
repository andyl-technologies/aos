{
  pkgs,
  lib,
  testing,
  mode,
  system,
}: let
  campaignComposition = {inherit mode system;};
  instructionFaults = import ./phase2-qemu-instruction-faults.nix {
    inherit pkgs lib testing campaignComposition;
  };
  hardwareFaults = import ./phase2-qemu-hardware-error-faults.nix {
    inherit pkgs lib testing campaignComposition;
  };
  pluginInstall = import ./phase2-qemu-live-plugin-install.nix {
    inherit pkgs lib testing campaignComposition;
  };
  blockRealization = import ./phase2-qemu-live-block-realization.nix {
    inherit pkgs lib testing campaignComposition;
  };
  patchMicrotests = import ./phase2-patch-microtests.nix {
    inherit pkgs lib testing campaignComposition;
  };
  checkpointMaterialization = import ./phase9-campaign-mode-checkpoint-materialization.nix {
    inherit pkgs lib testing mode system;
  };
  replayOracle = import ./phase9-campaign-mode-replay-oracle.nix {
    inherit pkgs lib testing mode system;
  };
  hotForkAtomicWorld = import ./phase7-qemu-hot-fork-atomic-world-vm.nix {
    inherit pkgs lib testing campaignComposition;
  };
  hotForkEquivalence = import ./phase7-qemu-hot-fork-equivalence-vm.nix {
    inherit pkgs lib testing campaignComposition;
  };
  campaignContinuity = import ./phase9-campaign-mode-native-campaign-continuity.nix {
    inherit pkgs lib testing mode system;
  };
in
  import ./phase7-signal-fault-system.nix {
    inherit
      pkgs
      lib
      testing
      campaignComposition
      instructionFaults
      hardwareFaults
      pluginInstall
      blockRealization
      patchMicrotests
      checkpointMaterialization
      replayOracle
      hotForkAtomicWorld
      hotForkEquivalence
      campaignContinuity
      ;
  }
