##! Procfs implementation of the canonical kernel-tunable interface.
{lib, ...}: let
  interface = lib.abilities.interfaces.kernelTunables.interface;
  artifact = lib.abilities.packageOutput {};
  effectsAlias = "kernel-tunable-effects";
  effectsDeclaration = lib.abilities.declareInterface {
    name = "aos.kernel.tunable-effects";
    description = "Executes admitted kernel-tunable operations for one exact controller-owned resource.";
    abi = 1;
    inherit (interface.declaration) requestType methods lifecycle;
    outputs = {};
    guarantees = [];
    aggregation = interface.declaration.aggregation // {controllerGroup = effectsAlias;};
  };
  effectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration effectsDeclaration
  );
in {
  config.aos.abilities = {
    interfaces.${effectsAlias} = effectsDeclaration;

    implementations.kernel-tunables = {
      description = "Converges Linux kernel tunables through the checked procfs controller.";
      interface = interface.identity;
      inherit artifact;
      inherit (interface) methods;
      guarantees = [];
      requirements.effects = {
        alias = "effects";
        description = "Invokes the package-owned terminal kernel-tunable handler.";
        accepted_interfaces = [effectsIdentity];
        inherit (interface) methods;
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      providerModule = {
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "provider.nix";
      };
      desiredType = interface.realizationType;
      requiredFeatures = [];
    };

    implementations.${effectsAlias} = {
      description = "Executes authorized kernel-tunable operations through the package-owned procfs handler.";
      interface = effectsAlias;
      inherit artifact;
      inherit (interface) methods;
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "bin/aos-kernel-tunable-provider";
        arguments = interface.requestType;
        result = interface.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
}
