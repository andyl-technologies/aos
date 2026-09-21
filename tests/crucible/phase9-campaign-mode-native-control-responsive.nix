{
  pkgs,
  lib,
  ...
} @ args: let
  authority = import ./phase5-control-responsive.nix {inherit pkgs lib;};
in
  import ./phase9-campaign-mode-native-gate.nix (args
    // {
      gate = "gate:control-responsive";
      authoritativeAttr = "checks.crucible.phase5.gates.controlResponsive";
      inherit authority;
      name = "native-control-responsive";
      cargoBuildCommands = [
        "test --frozen --offline --no-run -p crucible-session --test gate_control_responsive"
        "test --frozen --offline --no-run -p crucible-api --test gate_control_responsive"
        "test --frozen --offline --no-run -p crucible-daemon --test gate_control_responsive"
      ];
      installedTests = [
        {
          targetName = "gate_control_responsive";
          targetKind = "test";
          crateDir = "crucible-session";
          destination = "crucible-session-gate-control-responsive";
        }
        {
          targetName = "gate_control_responsive";
          targetKind = "test";
          crateDir = "crucible-api";
          destination = "crucible-api-gate-control-responsive";
        }
        {
          targetName = "gate_control_responsive";
          targetKind = "test";
          crateDir = "crucible-daemon";
          destination = "crucible-daemon-gate-control-responsive";
        }
      ];
      runtimeCommands = [
        {
          executable = "crucible-session-gate-control-responsive";
          arguments = [];
          expectedCount = 5;
          evidence = "crucible_session_gate_control_responsive";
        }
        {
          executable = "crucible-api-gate-control-responsive";
          arguments = [];
          expectedCount = 6;
          evidence = "crucible_api_gate_control_responsive";
        }
        {
          executable = "crucible-daemon-gate-control-responsive";
          arguments = [];
          expectedCount = 3;
          evidence = "crucible_daemon_gate_control_responsive";
        }
      ];
    })
