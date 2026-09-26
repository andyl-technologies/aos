##! Independent ingress requests retain distinct fragments in one ruleset.
{lib}: let
  provider = import ../../pkgs/networking/_aos-network-ruleset-provider/provider.nix {
    inherit lib;
    config = {};
    packageName = "aos-network-ruleset-provider";
  };
  provide = provider.config.aos.abilities.implementations.network-ingress-policy.provide;
  parameters = {
    endpoints = [
      {
        transport = "tcp";
        port = 443;
      }
    ];
    prerequisites = [];
  };
  request = consumer: {
    inherit consumer parameters;
    scope = ["host"];
  };
  context = {
    instance.id = "network-provider";
    requests = {
      first = request "service-a";
      second = request "service-b";
    };
    bindings = {
      first = {
        request = "first";
        slot = "ingress-a";
      };
      second = {
        request = "second";
        slot = "ingress-b";
      };
    };
  };
  result = provide context;
  first = result.resourceFragments.ingress-a.value.ingress;
  second = result.resourceFragments.ingress-b.value.ingress;
in
  assert builtins.length (builtins.attrNames first) == 1;
  assert builtins.length (builtins.attrNames second) == 1;
  assert builtins.head (builtins.attrNames first) != builtins.head (builtins.attrNames second);
  assert builtins.head (builtins.attrValues first) == parameters;
  assert builtins.head (builtins.attrValues second) == parameters; true
