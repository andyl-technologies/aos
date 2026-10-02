##! Checks native DNS listener ownership, configuration, and conflicting claims.
{
  lib,
  self,
  pkgs,
}: let
  evaluated = lib.evalPackageModules {
    scope = ["test" "bind"];
    packages = [self];
    operatorModules = [
      {
        aos.services.bind = {
          enable = true;
          port = 5353;
          listenIPv6 = [];
        };
      }
    ];
  };
  config = evaluated.config;
  conflicting = lib.evalPackageModules {
    scope = ["test" "conflicting-dns"];
    packages = [self pkgs.dnsmasq];
    operatorModules = [
      {
        aos.services = {
          bind = {
            enable = true;
            port = 5353;
          };
          dnsmasq = {
            enable = true;
            port = 5353;
          };
        };
      }
    ];
  };
in {
  listeners = assert builtins.attrNames config.aos.abilities.listener.operations.claim.effects == ["tcp-5353" "udp-5353"]; true;
  ingress = assert config.aos.networkPolicy.ingress.bind.endpoints
  == [
    {
      transport = "tcp";
      port = 5353;
    }
    {
      transport = "udp";
      port = 5353;
    }
  ]; true;
  settings = assert builtins.all (value: value.assertion) evaluated.assertions;
  assert config.aos.services.bind.policy.hardening.operation_profile == "privileged";
  assert config.aos.services.bind.policy.hardening.operation_allow == [];
  assert config.aos.services.bind.policy.hardening.operation_deny == [];
  assert config.aos.services.bind.isolation.home_access == "inaccessible";
  assert config.aos.services.bind.reload.strategy == "command";
  assert config.aos.abilities.configuration.operations.file.effects.bind.input.fragments != []; true;
  conflictingOwnership = assert !(builtins.tryEval (builtins.deepSeq conflicting.config.aos.abilities.listener.operations.claim.effects.tcp-5353.outputs.resource true)).success; true;
}
