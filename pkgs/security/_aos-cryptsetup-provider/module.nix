##! Cryptsetup implementation of the canonical encrypted block-mapping resource.
{lib, ...}: let
  interface = lib.abilities.interfaces.blockStorage.interfaces.encryptedMapping;
  artifact = lib.abilities.packageOutput {};
  effectsAlias = "encrypted-block-mapping-effects";
  effectsDeclaration = lib.abilities.declareInterface {
    name = "aos.cryptsetup.encrypted-block-mapping-effects";
    description = "Executes admitted encrypted block-mapping operations.";
    abi = 1;
    inherit (interface.declaration) requestType methods lifecycle;
    outputs = {};
    guarantees = [];
    aggregation = interface.declaration.aggregation // {controllerGroup = effectsAlias;};
  };
  effectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration effectsDeclaration
  );
  realizationType = lib.abilities.types.record {
    fields = {
      schema = lib.abilities.types.enum ["aos.storage.encrypted-block-mapping-realization/v1"];
      cryptsetup = lib.abilities.types.executableReference;
    };
  };
in {
  config.aos.abilities = {
    interfaces.${effectsAlias} = effectsDeclaration;

    implementations.encrypted-block-mapping = {
      description = "Converges encrypted block mappings through the cryptsetup controller.";
      interface = interface.identity;
      inherit artifact;
      inherit (interface) methods;
      guarantees = [];
      requirements.effects = {
        alias = "effects";
        description = "Invokes the package-owned terminal cryptsetup handler.";
        accepted_interfaces = [effectsIdentity];
        inherit (interface) methods;
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      providerModule = {
        inherit artifact;
        path = "share/aos/providers/encrypted-block-mapping.nix";
      };
      desiredType = realizationType;
      requiredFeatures = [];
    };

    implementations.${effectsAlias} = {
      description = "Executes authorized encrypted block-mapping operations through cryptsetup.";
      interface = effectsAlias;
      inherit artifact;
      inherit (interface) methods;
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "bin/aos-cryptsetup-provider";
        arguments = interface.requestType;
        result = interface.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
}
