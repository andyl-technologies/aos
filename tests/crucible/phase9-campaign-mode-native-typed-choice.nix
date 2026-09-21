{
  pkgs,
  lib,
  ...
} @ args: let
  authority = import ./phase2-typed-choice.nix {inherit pkgs lib;};
in
  import ./phase9-campaign-mode-native-gate.nix (args
    // {
      gate = "gate:typed-choice";
      authoritativeAttr = "checks.crucible.phase2.gates.typedChoice";
      inherit authority;
      name = "native-typed-choice";
      cargoBuildCommands = [
        "test --frozen --offline --no-run -p crucible-campaign --lib --test gate_typed_choice"
        "test --frozen --offline --no-run -p crucible-protocol --lib"
        "test --frozen --offline --no-run -p crucible-guest --lib"
      ];
      installedTests = [
        {
          targetName = "crucible_campaign";
          targetKind = "lib";
          crateDir = "crucible-campaign";
          destination = "crucible-campaign-lib";
        }
        {
          targetName = "gate_typed_choice";
          targetKind = "test";
          crateDir = "crucible-campaign";
          destination = "gate-typed-choice";
        }
        {
          targetName = "crucible_protocol";
          targetKind = "lib";
          crateDir = "crucible-protocol";
          destination = "crucible-protocol-lib";
        }
        {
          targetName = "crucible_guest";
          targetKind = "lib";
          crateDir = "crucible-guest";
          destination = "crucible-guest-lib";
        }
      ];
      runtimeCommands = [
        {
          executable = "crucible-campaign-lib";
          arguments = [];
          expectedCount = 372;
          evidence = "crucible_campaign_lib";
        }
        {
          executable = "gate-typed-choice";
          arguments = [];
          expectedCount = 1;
          evidence = "gate_typed_choice";
        }
        {
          executable = "crucible-protocol-lib";
          arguments = ["selectable"];
          expectedCount = 17;
          evidence = "crucible_protocol_selectable";
        }
        {
          executable = "crucible-guest-lib";
          arguments = ["selectable"];
          expectedCount = 8;
          evidence = "crucible_guest_selectable";
        }
      ];
    })
