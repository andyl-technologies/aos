##! Checks native Tailscale device requirements, arguments, and documentation.
{
  lib,
  pkgs,
}: let
  evaluate = settings:
    lib.evalPackageModules {
      scope = ["test" "tailscale"];
      packages = [pkgs.tailscale];
      operatorModules = [{aos.services.tailscale = settings;}];
    };
  disabled = evaluate {enable = false;};
  enabled = evaluate {
    enable = true;
    port = 42641;
    extraArgs = ["--no-logs-no-support"];
  };
  config = enabled.config;
  command = builtins.head config.aos.services.tailscale.lifecycle.start;
  documentation = builtins.filter (option: option.owner == "tailscale") enabled.documentation.options;
in
  assert pkgs.tailscale ? module;
  assert disabled.config.aos.abilities.serviceManagement.operations.realize.effects == {};
  assert disabled.config.aos.abilities.device.operations.present.effects == {};
  assert config.aos.abilities.device.operations.present.effects.tailscale.input.path == "/dev/net/tun";
  assert config.aos.abilities.network.operations.ready.effects ? tailscale;
  assert command.executable.path == "${pkgs.tailscale}/bin/tailscaled";
  assert command.executable.arguments == ["--state=/var/lib/tailscale/tailscaled.state" "--socket=/run/tailscale/tailscaled.sock" "--port=42641" "--no-logs-no-support"];
  assert builtins.all (option: option.description != "") documentation;
  assert (import ../../pkgs/networking/_tailscale/runtime-tests.nix {cfg = config.aos.services.tailscale;}).description == "Tailscale service checks"; true
