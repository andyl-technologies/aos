{
  pkgs,
  lib,
  ...
} @ args: let
  authority = import ./phase7-crucible-campaign-continuity.nix {inherit pkgs lib;};
in
  import ./phase9-campaign-mode-native-gate.nix (args
    // {
      gate = "gate:campaign-continuity";
      authoritativeAttr = "checks.crucible.phase7.gates.campaignContinuity";
      inherit authority;
      name = "native-campaign-continuity";
      cargoBuildCommands = [
        "test --frozen --offline --no-run -p crucible-cas --test gate_campaign_continuity"
      ];
      installedTests = [
        {
          targetName = "gate_campaign_continuity";
          targetKind = "test";
          crateDir = "crucible-cas";
          destination = "gate-campaign-continuity";
        }
      ];
      runtimeCommands = [
        {
          executable = "gate-campaign-continuity";
          arguments = [];
          expectedCount = 4;
          evidence = "gate_campaign_continuity";
        }
      ];
    })
