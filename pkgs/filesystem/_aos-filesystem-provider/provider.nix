##! Pure resource projection for the AOS filesystem provider.
{
  config,
  lib,
  packageName,
  ...
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  emptyComposition = {
    requests = {};
    outputs = {};
    realizations = {};
  };
  effectsInterface = alias:
    lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration config.aos.abilities.interfaces."${packageName}:${alias}-effects"
    );
  withEffects = alias: resources: realizations:
    emptyComposition
    // {
      requests = builtins.mapAttrs (key: resource: {
        requirement = "effects";
        scope = ["effects"];
        slot = resource.resource.key;
        parameters = resource.value;
      }) resources;
      inherit realizations;
    };
  transitionFor = alias: action: resourceLifetime: context:
    lib.abilities.resourceControllerTransition {
      inherit context resourceLifetime;
      terminalInterface = effectsInterface alias;
      actions = {
        create = {
          method = action;
          phase = "converging";
          access = "exclusive-write";
        };
        update = {
          method = action;
          phase = "converging";
          access = "exclusive-write";
        };
        unchanged = null;
        remove = {
          method = "release";
          phase = "converging";
          access = "exclusive-write";
        };
        reconcile-stopped = {
          method = action;
          phase = "recovering";
          access = "exclusive-write";
        };
        reconcile-divergent = {
          method = action;
          phase = "recovering";
          access = "exclusive-write";
        };
      };
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
  # Provider contexts already contain normalized wire identities, so only the
  # enclosing reference marker remains to be attached here.
  referenceFor = interface: lifetime: resource: {
    _type = "aos-resource-reference";
    interface = interface.identity;
    inherit resource lifetime;
    operations = ["observe"];
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
  provide = interface: lifetime: plannedPath: publishedOutput: {
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
    emptyProvision
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value =
            {
              planned-path = plannedPath entry.resource entry.request.parameters;
            }
            // lib.optionalAttrs (publishedOutput != null) {
              ${publishedOutput} = referenceFor interface lifetime entry.resource;
            };
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
  storageCompose = alias: persistent: {resources, ...}:
    withEffects alias resources (builtins.mapAttrs (_: resource: {
          schema = "aos.filesystem.storage-realization/v1";
          path = storagePath persistent resource.resource resource.value;
        })
        resources);
  storageViewPath = request:
    if (request.relative_path or null) == null
    then request.source_path
    else
      lib.abilities.pathWithin {
        base = request.source_path;
        relativePath = request.relative_path;
      };
  storageViewProvide = {
    requests,
    bindings,
    ...
  }:
    emptyProvision
    // {
      outputs =
        builtins.mapAttrs (_: request: {
          planned-path = storageViewPath request.parameters;
        })
        requests;
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
    withEffects "storage-view" resources (builtins.mapAttrs (_: resource: {
          schema = "aos.filesystem.storage-view-realization/v1";
          inherit (resource.value) source;
          relative_path = resource.value.relative_path or null;
          path = storageViewPath resource.value;
        })
        resources);
  entryCompose = {resources, ...}:
    withEffects "filesystem-entry" resources (builtins.mapAttrs (_: resource: {
          schema = "aos.filesystem.entry-realization/v1";
          path = resource.value.destination;
          source_path = sourcePath resource.value.entry;
        })
        resources);
in {
  config.aos.abilities.implementations = {
    storage-allocation = {
      provide = provide interfaces.storageAllocation "instance" (storagePath false) null;
      compose = storageCompose "storage-allocation" false;
      transition = transitionFor "storage-allocation" "allocate" "instance";
    };
    persistent-storage-allocation = {
      provide = provide interfaces.persistentStorageAllocation "persistent" (storagePath true) null;
      compose = storageCompose "persistent-storage-allocation" true;
      transition = transitionFor "persistent-storage-allocation" "allocate" "persistent";
    };
    storage-view = {
      provide = storageViewProvide;
      compose = storageViewCompose;
      transition = transitionFor "storage-view" "materialize" "instance";
    };
    filesystem-entry = {
      provide = provide interfaces.filesystemEntry "instance" (_: request: request.destination) "entry-resource";
      compose = entryCompose;
      transition = transitionFor "filesystem-entry" "materialize" "instance";
    };
  };
}
