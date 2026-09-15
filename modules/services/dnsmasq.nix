##! Selects the package-owned dnsmasq service module for static systems.
{
  config,
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.dnsmasq pkgs.dnsutils];

  system.checks.dnsmasq = lib.mkIf config.aos.services.dnsmasq.enable {
    description = "dnsmasq service checks";
    checks = [
      {
        name = "dnsmasq-active";
        description = "dnsmasq remains active after startup";
        script = ''
          vm.wait_until_succeeds(
              "systemctl is-active --quiet dnsmasq.service", timeout=30
          )
        '';
      }
    ];
  };
}
