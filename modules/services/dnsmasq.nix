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
        name = "local-dns-query";
        description = "dnsmasq answers a local DNS request";
        script = ''
          vm.wait_until_succeeds(
              "dig -p ${toString config.aos.services.dnsmasq.port} @127.0.0.1 localhost A +short | grep -Fx 127.0.0.1",
              timeout=30,
          )
        '';
      }
    ];
  };
}
