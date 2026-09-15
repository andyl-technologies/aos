##! Package-owned kernel-module loading ability declarations.
{lib, ...}: let
  kernelModules = lib.abilities.interfaces.serviceManagement.interfaces.kernelModules;
  artifact = lib.abilities.packageOutput {};
  realizationType = lib.abilities.types.record {
    fields = {
      schema = lib.abilities.types.enum ["aos.kmod.module-set-realization/v1"];
      modules = lib.abilities.types.list {
        element = lib.abilities.types.localKey;
        maxItems = 256;
      };
      required = lib.abilities.types.boolean;
    };
  };
in {
  config.aos.abilities = {
    implementations.kernel-modules = {
      description = "Loads and observes exact kernel-module sets through libkmod.";
      interface = kernelModules.alias;
      inherit artifact;
      methods = kernelModules.methods;
      guarantees = [];
      providerModule = {
        inherit artifact;
        path = "share/aos/providers/kmod.nix";
      };
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "libexec/aos-kmod-handler";
        arguments = kernelModules.requestType;
        result = kernelModules.observationType;
      };
      desiredType = realizationType;
      requiredFeatures = [];
    };
  };
}
