{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.branchPointModel",
  taskIds ? ["T-CAM-4.1" "T-CAM-4.2" "T-CAM-4.3" "T-CAM-4.4"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase4-branch-point-model";

    buildDeps = [pkgs.coreutils] ++ dependencies;

    phases = [
      {
        name = "run-branch-point-model";
        script = ''
          set -eu

          crucible-cargo test \
            -p crucible-campaign \
            --test gate_branch_point_model \
            -- --test-threads=1

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:branch-point-model
          scope=parent-scoped-identity,finite-generated-convergence,lazy-cursors,semantic-deduplication,immutable-execution-basis,retained-causes,observation-credit,cold-restart,statistical-intervention-exclusion
          RESULT
        '';
      }
    ];
  }
