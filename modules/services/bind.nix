##! Enforces cross-package host listener policy.
{
  config,
  lib,
  ...
}: {
  assertions = lib.mkIf config.aos.services.bind.enable [
    {
      assertion = !(config.aos.services.dnsmasq.enable && config.aos.services.dnsmasq.port == config.aos.services.bind.port);
      message = "BIND and dnsmasq cannot both listen on the same DNS port";
    }
  ];
}
