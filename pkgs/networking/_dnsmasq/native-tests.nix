##! Checks native DNS and DHCP listeners, firewall ingress, and settings.
{
  lib,
  self,
  ...
}: let
  evaluated = lib.evalPackageModules {
    scope = ["test" "dnsmasq"];
    packages = [self];
    operatorModules = [
      {
        aos.services.dnsmasq = {
          enable = true;
          port = 5353;
          dhcpRanges = ["192.0.2.10,192.0.2.20,12h"];
        };
      }
    ];
  };
  config = evaluated.config;
in {
  listeners = assert builtins.attrNames config.aos.abilities.listener.operations.claim.effects == ["tcp-5353" "udp-5353" "udp-67"]; true;
  ingress = assert config.aos.networkPolicy.ingress.dnsmasq.endpoints
  == [
    {
      transport = "tcp";
      port = 5353;
    }
    {
      transport = "udp";
      port = 5353;
    }
    {
      transport = "udp";
      port = 67;
    }
  ]; true;
  settings = assert builtins.all (value: value.assertion) evaluated.assertions;
  assert config.aos.services.dnsmasq.policy.hardening.operation_profile == "privileged";
  assert config.aos.services.dnsmasq.policy.hardening.operation_allow == [];
  assert config.aos.services.dnsmasq.policy.hardening.operation_deny == [];
  assert config.aos.services.dnsmasq.lifecycle.configuration_change_action == "restart";
  assert config.aos.abilities.configuration.operations.file.effects.dnsmasq.input.fragments != []; true;
}
