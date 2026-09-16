##! Package-owned kernel-module loading ability declarations.
{lib, ...}: let
  kernelModules = lib.abilities.interfaces.serviceManagement.interfaces.kernelModules;
  artifact = lib.abilities.packageOutput {};
  effectsAlias = "kernel-module-effects";
  effectsDeclaration = lib.abilities.declareInterface {
    name = "aos.kernel.module-effects";
    description = "Executes admitted kernel-module operations for one exact controller-owned resource.";
    abi = 1;
    inherit (kernelModules.declaration) requestType methods lifecycle;
    outputs = {};
    guarantees = [];
    aggregation = kernelModules.declaration.aggregation // {controllerGroup = effectsAlias;};
  };
  effectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration effectsDeclaration
  );
  effectsRequirement = {
    alias = "effects";
    description = "Invokes the package-owned terminal kernel-module handler.";
    accepted_interfaces = [effectsIdentity];
    methods = kernelModules.methods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };
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
    interfaces.${effectsAlias} = effectsDeclaration;

    implementations.kernel-modules = {
      description = "Loads and observes exact kernel-module sets through libkmod.";
      interface = kernelModules.alias;
      inherit artifact;
      methods = kernelModules.methods;
      guarantees = [];
      requirements.effects = effectsRequirement;
      providerModule = {
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "provider.nix";
      };
      desiredType = realizationType;
      requiredFeatures = [];
    };

    implementations.${effectsAlias} = {
      description = "Executes authorized kernel-module operations through the package-owned libkmod handler.";
      interface = effectsAlias;
      inherit artifact;
      methods = kernelModules.methods;
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "libexec/aos-kmod-handler";
        arguments = kernelModules.requestType;
        result = kernelModules.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
}
