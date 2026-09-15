##! systemd-repart implementation of the portable storage-provisioning resource.
{
  config,
  lib,
  ...
}: let
  storage = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  artifact = lib.abilities.packageOutput {};
  terminalAlias = "storage-provisioning-effects";
  terminalDeclaration = lib.abilities.declareInterface {
    name = "aos.systemd-repart.storage-provisioning-effects";
    description = "Executes one admitted storage-provisioning transaction.";
    abi = 1;
    inherit (storage.declaration) requestType methods lifecycle;
    outputs = {};
    guarantees = [];
    aggregation = storage.declaration.aggregation // {controllerGroup = terminalAlias;};
  };
  terminalIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration terminalDeclaration
  );
  terminalRealization = lib.abilities.types.record {
    fields = {
      schema = lib.abilities.types.enum ["aos.storage.provisioning-realization/v1"];
      systemd_repart = lib.abilities.types.executableReference;
      blkid = lib.abilities.types.executableReference;
      lsblk = lib.abilities.types.executableReference;
      sfdisk = lib.abilities.types.executableReference;
      udevadm = lib.abilities.types.executableReference;
    };
  };
in {
  config.aos.abilities = {
    interfaces.${terminalAlias} = terminalDeclaration;

    implementations.storage-provisioning = {
      description = "Composes portable storage-provisioning resources into checked repart effects.";
      inherit artifact;
      interface = storage.identity;
      inherit (storage) methods;
      guarantees = [];
      requirements.effects = {
        alias = "effects";
        description = "Invokes the package-owned systemd-repart terminal handler.";
        accepted_interfaces = [terminalIdentity];
        inherit (storage) methods;
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      providerModule = {
        inherit artifact;
        path = "share/aos/providers/storage-provisioning.nix";
      };
      desiredType = terminalRealization;
      requiredFeatures = [];
    };

    implementations.${terminalAlias} = {
      description = "Executes checked systemd-repart storage provisioning.";
      inherit artifact;
      interface = terminalIdentity;
      inherit (storage) methods;
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "bin/aos-storage-provisioning-provider";
        arguments = storage.requestType;
        result = storage.observationType;
      };
      providerModule = null;
      desiredType = null;
      requiredFeatures = [];
    };
  };
}
