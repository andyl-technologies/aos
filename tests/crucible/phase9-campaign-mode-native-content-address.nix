{
  pkgs,
  lib,
  ...
} @ args: let
  authority = import ./phase1-content-address.nix {inherit pkgs lib;};
in
  import ./phase9-campaign-mode-native-gate.nix (args
    // {
      gate = "gate:content-address";
      authoritativeAttr = "checks.crucible.phase1.gates.contentAddress";
      inherit authority;
      name = "native-content-address";
      cargoBuildCommands = [
        "test --frozen --offline --no-run -p crucible --test predicate_dsl --test gate_content_address"
        "test --frozen --offline --no-run -p crucible-sim --test gate_content_address"
      ];
      installedTests = [
        {
          targetName = "predicate_dsl";
          targetKind = "test";
          crateDir = "crucible";
          destination = "crucible-predicate-dsl";
        }
        {
          targetName = "gate_content_address";
          targetKind = "test";
          crateDir = "crucible";
          destination = "crucible-gate-content-address";
        }
        {
          targetName = "gate_content_address";
          targetKind = "test";
          crateDir = "crucible-sim";
          destination = "crucible-sim-gate-content-address";
        }
      ];
      runtimeCommands = [
        {
          executable = "crucible-predicate-dsl";
          arguments = [];
          expectedCount = 2;
          evidence = "crucible_predicate_dsl";
        }
        {
          executable = "crucible-gate-content-address";
          arguments = [];
          expectedCount = 30;
          evidence = "crucible_gate_content_address";
        }
        {
          executable = "crucible-sim-gate-content-address";
          arguments = [];
          expectedCount = 5;
          evidence = "crucible_sim_gate_content_address";
        }
      ];
    })
