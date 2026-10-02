##! Owns the host firewall configuration and its native ruleset contract.
{
  config,
  lib,
  ...
}: let
  inherit (lib) mkOption types;
  operation = config.aos.abilities.networkPolicy.operations.ruleset;
  cfg = config.aos.networkPolicy;
in {
  config.system.checks.firewall = lib.mkIf cfg.enable (import ./runtime-tests.nix {});
  options.aos.networkPolicy = mkOption {
    type = types.submodule [
      operation.input
      {options.enable = (lib.mkEnableOption "the host firewall policy") // {extensible = true;};}
    ];
    default = {};
    extensible = true;
    description = "Merged host network policy enforced by the selected ruleset backend.";
  };

  config.aos.abilities.networkPolicy.operations.ruleset = {
    input.options = {
      defaultPolicy = mkOption {
        type = types.enum ["accept" "drop"];
        default = "drop";
        description = "Default policy for inbound traffic.";
      };
      forwardPolicy = mkOption {
        type = types.enum ["accept" "drop"];
        default = "drop";
        description = "Default policy for forwarded traffic.";
      };
      trustedInterfaces = mkOption {
        type = types.listOf types.str;
        default = ["lo"];
        description = "Network interfaces accepting all traffic.";
      };
      allowedTCP = mkOption {
        type = types.listOf (types.ints.between 1 65535);
        default = [];
        description = "TCP ports allowed inbound.";
      };
      allowedUDP = mkOption {
        type = types.listOf (types.ints.between 1 65535);
        default = [];
        description = "UDP ports allowed inbound.";
      };
    };
    input.options.ingress = mkOption {
      type = types.attrsOf (types.submodule {
        options.endpoints = mkOption {
          type = types.listOf (types.submodule {
            options = {
              transport = mkOption {
                type = types.enum ["tcp" "udp"];
                description = "Transport receiving the contributed allowance.";
              };
              port = mkOption {
                type = types.ints.between 1 65535;
                description = "Inbound port allowed by this contribution.";
              };
            };
          });
          default = [];
          description = "Additional inbound endpoints allowed by this package.";
        };
      });
      default = {};
      description = "Named inbound policy definitions merged before ruleset rendering.";
    };
    input.options.forwarding = mkOption {
      type = types.attrsOf (types.submodule {
        options.policy = mkOption {
          type = types.enum ["accept" "drop"];
          description = "Forwarding policy contributed by this package; drop takes priority.";
        };
      });
      default = {};
      description = "Named forwarding definitions enforced together with the base policy.";
    };
    result.options.resource = mkOption {
      type = types.str;
      description = "Installed ruleset identity returned by the backend.";
    };
    effects = lib.mkIf cfg.enable {
      host.input = builtins.removeAttrs cfg ["enable"];
    };
  };
}
