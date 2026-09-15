##! Selected pure controller for storage-dataset convergence.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "storage-dataset";
  interface = lib.abilities.interfaces.blockStorage.interfaces.dataset;
  controller = config.aos.abilities.implementations."${packageName}:${alias}";
  terminalInterface = builtins.head controller.requirements.effects.accepted_interfaces;
  emptyResult = {
    requests = {};
    outputs = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a storage-dataset request must have exactly one selected binding";
  reference = instance: key: {
    interface = interface.identity;
    resource = {
      provider = instance.id;
      inherit key;
    };
    operations = ["observe"];
    lifetime = "instance";
  };
  provide = {
    instance,
    requests,
    bindings,
    ...
  }: let
    entries = builtins.map (requestName: {
      inherit requestName;
      binding = bindingFor bindings requestName;
      parameters = requests.${requestName}.parameters;
    }) (builtins.attrNames requests);
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.readiness-resource = reference instance entry.binding.slot;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = interface.identity.name;
            lifetime = "instance";
            value = entry.parameters;
          };
        })
        entries);
    };
  compose = {resources, ...}:
    emptyResult
    // {
      requests =
        builtins.mapAttrs (key: resource: {
          requirement = "effects";
          scope = [key];
          slot = key;
          parameters = resource.value;
        })
        resources;
      realizations =
        builtins.mapAttrs (_: _: {
          schema = "aos.storage.dataset-realization/v1";
          zfs = {
            artifact = lib.abilities.packageOutput {package = "zfs";};
            entry_point = "sbin/zfs";
            arguments = [];
          };
        })
        resources;
    };
  transition = context:
    lib.abilities.resourceControllerTransition {
      inherit context terminalInterface;
      actions = {
        create = {
          method = "mount";
          phase = "converging";
          access = "exclusive-write";
        };
        update = {
          method = "mount";
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
          method = "mount";
          phase = "recovering";
          access = "exclusive-write";
        };
        reconcile-divergent = {
          method = "mount";
          phase = "recovering";
          access = "exclusive-write";
        };
      };
    };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide compose transition;};
}
