##! Provider-neutral host firewall policy contributed by the nftables package.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.firewall;
  abilityTypes = lib.abilities.types;
  networkPolicy = lib.abilities.interfaces.networkPolicy;
  consumerInstance = "firewall";
  ruleset = lib.abilities.interfaces.serviceManagement.forProducer {
    inherit consumerInstance;
    key = "ruleset";
    interface = networkPolicy.interfaces.ruleset;
    parameters = {
      base = {
        input_policy = cfg.defaultPolicy;
        forward_policy = cfg.forwardPolicy;
        trusted_interfaces = cfg.trustedInterfaces;
        prerequisites = [];
      };
      ingress.firewall-defaults = {
        endpoints =
          builtins.map (port: {
            transport = "tcp";
            inherit port;
          })
          cfg.allowedTCP
          ++ builtins.map (port: {
            transport = "udp";
            inherit port;
          })
          cfg.allowedUDP;
        prerequisites = [];
      };
      forwarding = {};
    };
  };
  contribution = lib.abilities.interfaces.serviceManagement.splitContribution ruleset;
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  ports = abilityTypes.list {
    element = port;
    maxItems = 4096;
    unique = true;
    canonicalOrder = true;
  };
  interfaceName = abilityTypes.string {
    maxLength = 64;
    syntax = null;
  };
in {
  options.aos.firewall = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Enable the provider-neutral host firewall policy.";
    };

    defaultPolicy = lib.mkOption {
      type = abilityTypes.enum ["accept" "drop"];
      default = "drop";
      description = "Default policy for inbound traffic.";
    };

    allowedTCP = lib.mkOption {
      type = ports;
      default = [];
      description = "TCP ports to allow inbound.";
    };

    allowedUDP = lib.mkOption {
      type = ports;
      default = [];
      description = "UDP ports to allow inbound.";
    };

    forwardPolicy = lib.mkOption {
      type = abilityTypes.enum ["accept" "drop"];
      default = "drop";
      description = "Default policy for forwarded traffic.";
    };

    trustedInterfaces = lib.mkOption {
      type = abilityTypes.list {
        element = interfaceName;
        maxItems = 256;
        unique = true;
        canonicalOrder = true;
      };
      default = ["lo"];
      description = "Network interfaces where all traffic is accepted unconditionally.";
    };
  };

  config = lib.mkMerge [
    {aos.abilities = contribution.declarations;}
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge [
        {instances.${consumerInstance} = {};}
        contribution.configured
        {
          runtimeChecks.firewall = {
            description = "nftables firewall checks";
            checks = [
              {
                name = "ruleset-loaded";
                description = "nftables ruleset is loaded";
                script = ''
                  vm.succeed("nft list ruleset")
                '';
              }
            ];
          };
        }
      ];
    })
  ];
}
