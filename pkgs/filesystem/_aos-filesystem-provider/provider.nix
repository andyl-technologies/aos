##! Pure resource projection for the AOS filesystem provider.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  emptyResult = {
    requests = {};
    outputs = {};
    resourceFragments = {};
    conditionalRequirements = [];
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches != 1
    then throw "a filesystem request must have exactly one selected binding"
    else builtins.head matches;
  resourceIdFor = instance: binding: {
    provider = instance.id;
    key = binding.slot;
  };
  defaultStoragePath = persistent: resource: let
    root =
      if persistent
      then "/var/lib/aos/storage"
      else "/run/aos/storage";
    digest = builtins.hashString "sha256" (builtins.toJSON resource);
  in "${root}/${digest}";
  storagePath = persistent: resource: request:
    request.requested_path or (defaultStoragePath persistent resource);
  sourcePath = entry:
    if entry.kind != "copied-file"
    then null
    else if entry.source.kind == "artifact-file"
    then "${entry.source.reference.artifact.store_path}/${entry.source.reference.path}"
    else entry.source.path;
  provide = interface: lifetime: plannedPath: {
    instance,
    requests,
    bindings,
    ...
  }: let
    entries = builtins.map (requestName: let
      request = requests.${requestName};
      binding = bindingFor bindings requestName;
      resource = resourceIdFor instance binding;
    in {
      inherit requestName request binding resource;
    }) (builtins.attrNames requests);
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.planned-path = plannedPath entry.resource entry.request.parameters;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = interface.identity.name;
            inherit lifetime;
            value = entry.request.parameters;
          };
        })
        entries);
    };
  storageCompose = persistent: {resources, ...}:
    emptyResult
    // {
      realizations = builtins.mapAttrs (_: resource: {
          schema = "aos.filesystem.storage-realization/v1";
          path = storagePath persistent resource.resource resource.value;
        })
        resources;
    };
  storageViewProvide = {requests, bindings, ...}:
    emptyResult
    // {
      resourceFragments = builtins.listToAttrs (builtins.map (requestName: let
          request = requests.${requestName};
          binding = bindingFor bindings requestName;
        in {
          name = binding.slot;
          value = {
            kind = interfaces.storageView.identity.name;
            lifetime = "instance";
            value = request.parameters;
          };
        }) (builtins.attrNames requests));
    };
  storageViewCompose = {resources, ...}:
    emptyResult
    // {
      realizations = builtins.mapAttrs (_: resource: {
          schema = "aos.filesystem.storage-view-realization/v1";
          inherit (resource.value) source;
          relative_path = resource.value.relative_path or null;
        })
        resources;
    };
  entryCompose = {resources, ...}:
    emptyResult
    // {
      realizations = builtins.mapAttrs (_: resource: {
          schema = "aos.filesystem.entry-realization/v1";
          path = resource.value.destination;
          source_path = sourcePath resource.value.entry;
        })
        resources;
    };
in {
  config.aos.abilities.implementations = {
    storage-allocation = {
      provide = provide interfaces.storageAllocation "instance" (storagePath false);
      compose = storageCompose false;
    };
    persistent-storage-allocation = {
      provide = provide interfaces.persistentStorageAllocation "persistent" (storagePath true);
      compose = storageCompose true;
    };
    storage-view = {
      provide = storageViewProvide;
      compose = storageViewCompose;
    };
    filesystem-entry = {
      provide = provide interfaces.filesystemEntry "instance" (_: request: request.destination);
      compose = entryCompose;
    };
  };
}
