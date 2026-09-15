args @ {
  pkgs,
  lib,
  ...
}: let
  authority = import ./phase6-checkpoint-materialization.nix {inherit pkgs lib;};
in
  assert authority.type == "derivation";
    import ./phase9-campaign-mode-native-gate.nix (args
      // {
        inherit authority;
        gate = "gate:checkpoint-materialization";
        authoritativeAttr = "checks.crucible.phase6.checkpointMaterialization";
        executionFamily = "qemu-runtime";
        name = "checkpoint-materialization";
        cargoBuildCommands = [
          "test --frozen --offline --release --no-run -p crucible --test gate_checkpoint_materialization"
        ];
        installedTests = [
          {
            targetName = "gate_checkpoint_materialization";
            targetKind = "test";
            crateDir = "crucible";
            destination = "crucible-gate-checkpoint-materialization";
          }
        ];
        runtimeCommands = [
          {
            executable = "crucible-gate-checkpoint-materialization";
            arguments = [];
            evidence = "exact_fat_and_thin_checkpoint_materialization";
            expectedCount = 1;
          }
        ];
      })
