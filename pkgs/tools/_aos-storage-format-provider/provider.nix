##! Selected pure controller for explicit storage-format convergence.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "storage-format";
  interface = lib.abilities.interfaces.blockStorage.interfaces.storageFormat;
  controller = config.aos.abilities.implementations."${packageName}:${alias}";
  effectsInterface = builtins.head controller.requirements.effects.accepted_interfaces;
  emptyResult = {
    requests = {};
    outputs = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a storage-format request must have exactly one selected binding";
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
    entries = builtins.map (requestName: let
      binding = bindingFor bindings requestName;
    in {
      inherit requestName binding;
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
          schema = "aos.storage.format-realization/v1";
          mkswap = {
            artifact = lib.abilities.packageOutput {package = "util-linux";};
            entry_point = "sbin/mkswap";
            arguments = [];
          };
          blkid = {
            artifact = lib.abilities.packageOutput {package = "util-linux";};
            entry_point = "sbin/blkid";
            arguments = [];
          };
        })
        resources;
    };
  transition = context:
    lib.abilities.resourceControllerTransition {
      inherit context;
      terminalInterface = effectsInterface;
      actions = {
        create = {
          method = "format";
          phase = "converging";
          access = "exclusive-write";
        };
        update = {
          method = "format";
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
          method = "format";
          phase = "recovering";
          access = "exclusive-write";
        };
        reconcile-divergent = {
          method = "format";
          phase = "recovering";
          access = "exclusive-write";
        };
      };
    };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide compose transition;};
}
