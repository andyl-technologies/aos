##! Provider-neutral kernel requirement and selected projection.
{lib, ...}: let
  consumer = "system:kernel";
  kernelInterface = lib.abilities.interfaces.kernelPlatform.interfaces.kernel;
in {
  imports = [./_kernel-selection.nix];

  config.aos.abilities = {
    instances.${consumer} = {};
    requirementTemplates."system:kernel" = {
      description = "Requires the system's package-owned kernel artifact provider.";
      interface = kernelInterface.identity.name;
      inherit (kernelInterface.identity) abi descriptor;
    };
    requests."system:kernel" = {
      requirement = "system:kernel";
      inherit consumer;
      parameters = true;
    };
  };
}
