{
  pkgs,
  lib,
  ...
} @ args: let
  authority = import ./phase1-divergence-bisect.nix {inherit pkgs lib;};
in
  import ./phase9-campaign-mode-native-gate.nix (args
    // {
      gate = "gate:divergence-bisect";
      authoritativeAttr = "checks.crucible.phase1.gates.divergenceBisect";
      inherit authority;
      name = "native-divergence-bisect";
      cargoBuildCommands = [
        "test --frozen --offline --no-run -p crucible-harness --test gate_divergence_bisect"
      ];
      installedTests = [
        {
          targetName = "gate_divergence_bisect";
          targetKind = "test";
          crateDir = "crucible-harness";
          destination = "gate-divergence-bisect";
        }
      ];
      runtimeCommands = [
        {
          executable = "gate-divergence-bisect";
          arguments = [];
          expectedCount = 14;
          evidence = "gate_divergence_bisect";
        }
      ];
    })
