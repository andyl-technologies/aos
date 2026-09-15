##! Native controller and terminal declarations for mutable filesystem resources.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  types = lib.abilities.types;
  artifact = lib.abilities.packageOutput {};
  providerModule = {
    inherit artifact;
    path = "share/aos/providers/filesystem.nix";
  };
  storageRealization = types.record {
    fields = {
      schema = types.enum ["aos.filesystem.storage-realization/v1"];
      path = serviceManagement.types.storagePath;
    };
  };
  viewRealization = types.record {
    fields = {
      schema = types.enum ["aos.filesystem.storage-view-realization/v1"];
      source = types.resourceReference;
      path = serviceManagement.types.storagePath;
      relative_path = {
        type = types.optional types.relativePath;
        optional = true;
      };
    };
  };
  entryRealization = types.record {
    fields = {
      schema = types.enum ["aos.filesystem.entry-realization/v1"];
      path = serviceManagement.types.executionPath;
      source_path = {
        type = types.optional serviceManagement.types.executionPath;
        optional = true;
      };
    };
  };
  kinds = {
    storage-allocation = {
      interface = interfaces.storageAllocation;
      realization = storageRealization;
      action = "allocate";
      description = "Allocates instance-scoped storage through the AOS filesystem controller.";
    };
    persistent-storage-allocation = {
      interface = interfaces.persistentStorageAllocation;
      realization = storageRealization;
      action = "allocate";
      description = "Allocates retained storage through the AOS filesystem controller.";
    };
    storage-view = {
      interface = interfaces.storageView;
      realization = viewRealization;
      action = "materialize";
      description = "Resolves authorized child views through the AOS filesystem controller.";
    };
    filesystem-entry = {
      interface = interfaces.filesystemEntry;
      realization = entryRealization;
      action = "materialize";
      description = "Materializes declared directories and copied files through the AOS filesystem controller.";
    };
  };
  effectsAlias = alias: "${alias}-effects";
  effectsName = alias: "aos.filesystem.${effectsAlias alias}";
  effectsDeclaration = alias: selected:
    lib.abilities.declareInterface {
      name = effectsName alias;
      description = "Executes checked terminal effects for ${selected.interface.document.interface.name}.";
      abi = 1;
      requestType = selected.interface.requestType;
      outputs = {};
      methods = builtins.mapAttrs (_: method: method // {
        targetResource = selected.interface.identity.name;
      }) selected.interface.declaration.methods;
      lifecycle = selected.interface.declaration.lifecycle;
      aggregation = selected.interface.declaration.aggregation // {
        controllerGroup = effectsAlias alias;
      };
      configurationType = null;
      guarantees = [];
    };
  effectsIdentity = alias: selected:
    lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration (effectsDeclaration alias selected)
    );
  effectsRequirement = alias: selected: {
    alias = "effects";
    description = "Selects the checked lower filesystem effect handler for ${selected.interface.identity.name}.";
    accepted_interfaces = [(effectsIdentity alias selected)];
    inherit (selected.interface) methods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  controllerImplementation = alias: selected: {
    name = alias;
    value = {
      inherit (selected) description;
      interface = selected.interface.identity;
      inherit artifact providerModule;
      inherit (selected.interface) methods;
      guarantees = [];
      requirements.effects = effectsRequirement alias selected;
      desiredType = selected.realization;
      requiredFeatures = [];
    };
  };
  terminalImplementation = alias: selected: {
    name = effectsAlias alias;
    value = {
      description = "Executes checked terminal effects for ${selected.interface.identity.name}.";
      interface = effectsAlias alias;
      inherit artifact;
      inherit (selected.interface) methods;
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "libexec/aos-${effectsAlias alias}";
        arguments = selected.interface.requestType;
        result = selected.interface.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
in {
  config.aos.abilities = {
    interfaces = builtins.listToAttrs (builtins.map (alias: {
        name = effectsAlias alias;
        value = effectsDeclaration alias kinds.${alias};
      }) (builtins.attrNames kinds));
    implementations = builtins.listToAttrs (
      builtins.map (alias: controllerImplementation alias kinds.${alias}) (builtins.attrNames kinds)
      ++ builtins.map (alias: terminalImplementation alias kinds.${alias}) (builtins.attrNames kinds)
    );
  };
}
