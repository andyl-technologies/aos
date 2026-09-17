##! Package-owned requirements for the selected kernel and system manager.
{
  config,
  lib,
  ...
}: let
  kernel = lib.abilities.interfaces.kernelPlatform.interfaces.kernel;
  manager = lib.abilities.interfaces.systemManager.interfaces.manager;
  configured = config.aos.abilities.environment != null;
in {
  config.aos.abilities = {
    requirementTemplates = {
      kernel = {
        description = "Requires the system's package-owned kernel artifact provider.";
        interface = kernel.identity.name;
        inherit (kernel.identity) abi descriptor;
      };
      system-manager = {
        description = "Requires the system's package-owned manager implementation.";
        interface = manager.identity.name;
        inherit (manager.identity) abi descriptor;
      };
    };

    instances = lib.mkIf configured {
      kernel = {};
      system-manager = {};
    };

    requests = lib.mkIf configured {
      kernel = {
        requirement = "kernel";
        consumer = "kernel";
        parameters = true;
      };
      system-manager = {
        requirement = "system-manager";
        consumer = "system-manager";
        parameters = true;
      };
    };
  };
}
