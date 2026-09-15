##! Native provider declarations for mutable filesystem resources.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  types = lib.abilities.types;
  artifact = lib.abilities.packageOutput {};
  handler = interface: {
    inherit artifact;
    entryPoint = "libexec/aos-filesystem-provider";
    arguments = interface.requestType;
    result = interface.observationType;
  };
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
  implementation = interface: desiredType: description: {
    inherit description desiredType providerModule;
    interface = interface.alias;
    inherit artifact;
    inherit (interface) methods;
    guarantees = [];
    handlerDescriptor = handler interface;
    requiredFeatures = [];
  };
in {
  config.aos.abilities = {
    implementations = {
      storage-allocation =
        implementation interfaces.storageAllocation storageRealization
        "Allocates instance-scoped storage through the AOS filesystem provider.";
      persistent-storage-allocation =
        implementation interfaces.persistentStorageAllocation storageRealization
        "Allocates retained storage through the AOS filesystem provider.";
      storage-view =
        implementation interfaces.storageView viewRealization
        "Resolves authorized child views through the AOS filesystem provider.";
      filesystem-entry =
        implementation interfaces.filesystemEntry entryRealization
        "Materializes declared directories and copied files through the AOS filesystem provider.";
    };
  };
}
