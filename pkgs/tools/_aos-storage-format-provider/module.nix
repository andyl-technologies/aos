##! Util-linux implementation of the canonical storage-format resource.
{lib, ...}: let
  interface = lib.abilities.interfaces.blockStorage.interfaces.storageFormat;
  artifact = lib.abilities.packageOutput {};
  effectsAlias = "storage-format-effects";
  effectsDeclaration = lib.abilities.declareInterface {
    name = "aos.util-linux.storage-format-effects";
    description = "Executes admitted storage-format operations.";
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
      schema = lib.abilities.types.enum ["aos.storage.format-realization/v1"];
      mkswap = lib.abilities.types.executableReference;
      blkid = lib.abilities.types.executableReference;
    };
  };
in {
  config.aos.abilities = {
    interfaces.${effectsAlias} = effectsDeclaration;
    implementations.storage-format = {
      description = "Converges explicit storage formats through the util-linux controller.";
      interface = interface.identity;
      inherit artifact;
      inherit (interface) methods;
      guarantees = [];
      requirements.effects = {
        alias = "effects";
        description = "Invokes the package-owned terminal storage-format handler.";
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
      desiredType = realizationType;
      requiredFeatures = [];
    };
    implementations.${effectsAlias} = {
      description = "Executes authorized storage formatting through util-linux.";
      interface = effectsAlias;
      inherit artifact;
      inherit (interface) methods;
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "bin/aos-storage-format-provider";
        arguments = interface.requestType;
        result = interface.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
}
