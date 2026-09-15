{
  pkgs,
  lib,
  ...
} @ args: let
  authority = import ./phase6-state-space-search.nix {inherit pkgs lib;};
in
  import ./phase9-campaign-mode-native-gate.nix (args
    // {
      gate = "gate:state-space-search";
      authoritativeAttr = "checks.crucible.phase6.stateSpaceSearch";
      inherit authority;
      name = "native-state-space-search";
      cargoBuildCommands = [
        "test --frozen --offline --no-run -p crucible --lib --test gate_state_space_search"
      ];
      installedTests = [
        {
          targetName = "gate_state_space_search";
          targetKind = "test";
          crateDir = "crucible";
          destination = "gate-state-space-search";
        }
        {
          targetName = "crucible";
          targetKind = "lib";
          crateDir = "crucible";
          destination = "crucible-lib";
        }
      ];
      runtimeCommands = [
        {
          executable = "gate-state-space-search";
          arguments = [];
          expectedCount = 4;
          evidence = "gate_state_space_search";
        }
        {
          executable = "crucible-lib";
          arguments = ["model::fault_signal::binding_runtime_test::finite_binding_search_choices_replay_once_and_reject_unused_overrides" "--exact"];
          expectedCount = 1;
          evidence = "finite_binding_search_replay";
        }
      ];
    })
