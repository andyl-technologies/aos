{
  pkgs,
  lib,
  ...
} @ args: let
  authority = import ./phase3-adversarial-determinism.nix {inherit pkgs lib;};
in
  import ./phase9-campaign-mode-native-gate.nix (args
    // {
      gate = "gate:adversarial-determinism";
      authoritativeAttr = "checks.crucible.phase3.gates.adversarialDeterminism";
      inherit authority;
      name = "native-adversarial-determinism";
      cargoBuildCommands = [
        "test --frozen --offline --no-run -p crucible-harness --test gate_adversarial_determinism"
        "test --frozen --offline --no-run -p crucible --test gate_adversarial_determinism"
      ];
      installedTests = [
        {
          targetName = "gate_adversarial_determinism";
          targetKind = "test";
          crateDir = "crucible-harness";
          destination = "crucible-harness-gate-adversarial-determinism";
        }
        {
          targetName = "gate_adversarial_determinism";
          targetKind = "test";
          crateDir = "crucible";
          destination = "crucible-gate-adversarial-determinism";
        }
      ];
      runtimeCommands = [
        {
          executable = "crucible-harness-gate-adversarial-determinism";
          arguments = [];
          expectedCount = 5;
          evidence = "crucible_harness_gate_adversarial_determinism";
        }
        {
          executable = "crucible-gate-adversarial-determinism";
          arguments = [];
          expectedCount = 2;
          evidence = "crucible_gate_adversarial_determinism";
        }
      ];
    })
