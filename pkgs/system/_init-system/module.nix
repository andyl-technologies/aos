##! Declares the retained command prepared for the next startup.
{
  config,
  lib,
  ...
}: let
  operation = config.aos.abilities.initSystem.operations.install;
  enabled = lib.filterAttrs (_: effect: effect.enable) operation.effects;
in {
  options.aos.initSystem = {
    container = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether the target prepares an initial process in a container deployment.";
    };
    containerStartupExecutable = lib.mkOption {
      type = lib.types.nullOr lib.types.pathInStore;
      default = null;
      description = "Retained runtime executable that activates deferred effects after a container manager starts.";
    };
  };

  config.aos.abilities.initSystem.operations.install = {
    input.options = {
      executable = lib.mkOption {
        type = lib.types.pathInStore;
        description = "Retained executable launched as the initial process on the next startup.";
      };
      arguments = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Ordered arguments passed to the initial executable.";
      };
    };
    result.options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Installed startup configuration consumed before launching the initial process.";
      };
      resource = lib.mkOption {
        type = lib.types.str;
        description = "Owned startup configuration resource identity.";
      };
    };
  };
  config.assertions = [
    {
      assertion = builtins.length (builtins.attrNames enabled) <= 1;
      message = "A target may prepare only one enabled initSystem.install command.";
    }
  ];
}
