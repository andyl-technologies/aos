##! Selected pure controller for the kmod kernel-module provider.
{
  config,
  lib,
  packageName,
  ...
}: let
  kernelModules = lib.abilities.interfaces.serviceManagement.interfaces.kernelModules;
  controller = config.aos.abilities.implementations."${packageName}:kernel-modules";
  effectsInterface = builtins.head controller.requirements.effects.accepted_interfaces;

  emptyResult = {
    requests = {};
    outputs = {};
  };

  checkedParameters = parameters: let
    moduleNames = parameters.modules;
    uniqueNames = builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = true;
      })
      moduleNames));
  in
    if moduleNames == []
    then throw "a kernel-module request must name at least one module"
    else if builtins.length moduleNames != builtins.length uniqueNames
    then throw "a kernel-module request cannot contain duplicate module names"
    else parameters // {modules = builtins.sort builtins.lessThan moduleNames;};

  bindingFor = bindings: requestName: let
    matches =
      builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches != 1
    then throw "a kernel-module request must have exactly one selected binding"
    else builtins.head matches;

  resourceReference = instance: key: {
    interface = kernelModules.identity;
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
    requestNames = builtins.attrNames requests;
    entries =
      builtins.map (requestName: let
        binding = bindingFor bindings requestName;
        parameters = checkedParameters requests.${requestName}.parameters;
      in {
        inherit requestName binding parameters;
      })
      requestNames;
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.readiness-resource = resourceReference instance entry.binding.slot;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = kernelModules.identity.name;
            lifetime = "instance";
            value = entry.parameters;
          };
        })
        entries);
    };

  effectRequest = key: resource: {
    requirement = "effects";
    scope = [key];
    slot = key;
    parameters = resource.value;
  };

  compose = {resources, ...}:
    emptyResult
    // {
      requests = builtins.mapAttrs effectRequest resources;
      realizations =
        builtins.mapAttrs (_: resource: {
          schema = "aos.kmod.module-set-realization/v1";
          inherit (resource.value) modules required;
        })
        resources;
    };

  transition = context:
    lib.abilities.resourceControllerTransition {
      inherit context;
      terminalInterface = effectsInterface;
      actions = {
        create = {
          method = "load";
          phase = "converging";
          access = "exclusive-write";
        };
        update = {
          method = "load";
          phase = "converging";
          access = "exclusive-write";
        };
        unchanged = null;
        remove = null;
        reconcile-stopped = {
          method = "load";
          phase = "recovering";
          access = "exclusive-write";
        };
        reconcile-divergent = {
          method = "load";
          phase = "recovering";
          access = "exclusive-write";
        };
      };
    };
in {
  config.aos.abilities.implementations.kernel-modules = {
    inherit provide compose transition;
  };
}
