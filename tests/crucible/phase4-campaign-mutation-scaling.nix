{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.campaignMutationScaling",
  taskIds ? ["T-CAM-4.10"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase4-campaign-mutation-scaling";

    buildDeps = [pkgs.coreutils] ++ dependencies;

    phases = [
      {
        name = "run-campaign-mutation-scaling";
        script = ''
          set -eu

          crucible-cargo test \
            -p crucible-campaign \
            --features test-support \
            --test gate_campaign_mutation_scaling \
            -- --test-threads=1

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-mutation-scaling
          mutations=10000
          scope=bounded-hot-validation,complete-cold-validation,failure-atomic-checkpoints,deep-closure-authentication,exact-result-locators
          RESULT
        '';
      }
    ];
  }
