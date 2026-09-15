##! Native implementation of the provider-neutral boot preparation interface.
{lib, ...}: let
  interface = lib.abilities.interfaces.bootPreparation.interfaces.preparation;
  artifact = lib.abilities.packageOutput {};
  realizationType = lib.abilities.types.record {
    fields.schema = lib.abilities.types.enum ["aos.boot.preparation-realization/v1"];
  };
in {
  config.aos.abilities.implementations.boot-preparation = {
    description = "Executes exact transaction-scoped boot preparation commands.";
    interface = interface.identity;
    inherit artifact;
    desiredType = realizationType;
    inherit (interface) methods;
    guarantees = [];
    providerModule = {
      inherit artifact;
      path = "share/aos/providers/boot-preparation.nix";
    };
    handlerDescriptor = {
      inherit artifact;
      entryPoint = "bin/aos-boot-preparation-provider";
      arguments = interface.requestType;
      result = interface.observationType;
    };
    requiredFeatures = [];
  };
}
