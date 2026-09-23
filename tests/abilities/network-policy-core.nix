##! Verifies canonical provider-neutral network-policy declarations.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  networkPolicy = lib.abilities.interfaces.networkPolicy;
  definitions = lib.mkMerge [
    {instances.workload = {};}
    (serviceManagement.forProducer {
      consumerInstance = "workload";
      key = "kerberos-ingress";
      interface = networkPolicy.interfaces.ingress;
      methods = ["observe"];
      parameters = {
        endpoints = [
          {
            transport = "tcp";
            port = 749;
          }
          {
            transport = "tcp";
            port = 88;
          }
          {
            transport = "udp";
            port = 88;
          }
        ];
        prerequisites = [];
      };
    })
    (serviceManagement.forProducer {
      consumerInstance = "workload";
      key = "packet-forwarding";
      interface = networkPolicy.interfaces.forwarding;
      methods = ["observe"];
      parameters = {
        policy = "accept";
        prerequisites = [];
      };
    })
  ];
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      ../../modules/abilities/default.nix
      {
        aos.abilities.environment = {
          authority = "test";
          key = "network-policy-core";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "consumer";
        module.config.aos.abilities = definitions;
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  ingress = abilities.requests."consumer:kerberos-ingress";
  forwarding = abilities.requests."consumer:packet-forwarding";
  ingressIdentity = networkPolicy.interfaces.ingress.identity;
in
  assert abilities.interfaces.network-ingress-policy.name == "aos.network.ingress-policy";
  assert abilities.interfaces.network-forwarding-policy.name == "aos.network.forwarding-policy";
  assert abilities.interfaces.network-ruleset.name == "aos.network.ruleset";
  assert abilities.requirementTemplates."consumer:network-ingress-policy".interface == ingressIdentity.name;
  assert abilities.requirementTemplates."consumer:network-ingress-policy".methods == ["observe"];
  assert ingress.parameters.endpoints
  == [
    {
      transport = "tcp";
      port = 749;
    }
    {
      transport = "tcp";
      port = 88;
    }
    {
      transport = "udp";
      port = 88;
    }
  ];
  assert abilities.requirementTemplates."consumer:network-forwarding-policy".interface
  == networkPolicy.interfaces.forwarding.identity.name;
  assert forwarding.parameters.policy == "accept"; true
