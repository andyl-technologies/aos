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
        name = "tailscale-local-api";
        description = "tailscaled creates its protected local API socket";
        script = ''
          vm.succeed("test -S /run/tailscale/tailscaled.sock")
          vm.wait_until_succeeds(
              "tailscale --socket=/run/tailscale/tailscaled.sock debug prefs "
              "| grep -F '\"LoggedOut\": true'",
              timeout=30,
          )
        '';
      }
    ];
  };
}
