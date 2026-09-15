##! Selects the package-owned Tailscale service module for static systems.
{
  config,
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [
    pkgs.tailscale
    pkgs.getent
    pkgs.iproute2
    pkgs.iptables
    pkgs.procps-ng
  ];

  system.checks.tailscale = lib.mkIf config.aos.services.tailscale.enable {
    description = "Tailscale service checks";
    checks = [
      {
        name = "tailscaled-active";
        description = "tailscaled reaches its ready state";
        script = ''
          vm.wait_until_succeeds(
              "systemctl is-active --quiet tailscaled.service", timeout=30
          )
        '';
      }
      {
        name = "tailscale-local-api";
        description = "tailscaled creates its protected local API socket";
        script = ''
          vm.succeed("test -S /run/tailscale/tailscaled.sock")
          vm.succeed(
              "tailscale --socket=/run/tailscale/tailscaled.sock debug prefs "
              "| grep -F '\"LoggedOut\": true'"
          )
        '';
      }
    ];
  };
}
