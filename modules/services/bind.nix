##! Selects the package-owned BIND DNS service module for static systems.
{
  config,
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.bind pkgs.dnsutils];

  assertions = lib.mkIf config.aos.services.bind.enable [
    {
      assertion = !(config.aos.services.dnsmasq.enable && config.aos.services.dnsmasq.port == config.aos.services.bind.port);
      message = "BIND and dnsmasq cannot both listen on the same DNS port";
    }
  ];

  system.checks.bind = lib.mkIf config.aos.services.bind.enable {
    description = "BIND DNS service checks";
    checks = [
      {
        name = "dns-query";
        description = "named answers a DNS request through its configured listener";
        script = ''
          vm.wait_until_succeeds(
              "dig -p ${toString config.aos.services.bind.port} @127.0.0.1 version.bind TXT CH +short",
              timeout=30,
          )
        '';
      }
    ];
  };
}
