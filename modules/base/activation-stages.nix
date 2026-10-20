##! Separates host and early-boot module evaluation scopes.
{lib, ...}: let
  inherit (lib) mkOption types;
in {
  options.aos.activation.stages = mkOption {
    type = types.attrsOf (types.submodule {
      options.configuration = mkOption {
        type = types.listOf types.pathInStore;
        default = [];
        description = "Ordered immutable operator module files replayed with this stage's package modules.";
      };
      options.supplementalInputs = mkOption {
        type = types.listOf types.pathInStore;
        default = [];
        description = "Immutable store roots retained and admitted with this stage without importing them as configuration.";
      };
      options.configurationBuilders = mkOption {
        type = types.listOf (types.functionTo (types.submodule {
          options = {
            packages = mkOption {type = types.listOf types.package;};
            configuration = mkOption {type = types.listOf types.pathInStore;};
            supplementalInputs = mkOption {
              type = types.listOf types.pathInStore;
              default = [];
            };
          };
        }));
        default = [];
        description = "Domain-owned producers append native packages and immutable configuration sources before final stage evaluation. Each producer receives only the preceding stage inputs.";
      };
    });
    default = {
      host = {};
      initrd = {};
    };
    description = "Independent deployment stages composed from retained module sources.";
  };
}
