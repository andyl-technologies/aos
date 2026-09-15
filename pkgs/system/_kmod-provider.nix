##! Selected pure composition for the kmod kernel-module provider.
{lib, ...}: let
  kernelModules = lib.abilities.interfaces.serviceManagement.interfaces.kernelModules;

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
    matches = builtins.filter
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
    entries = builtins.map (requestName: let
      binding = bindingFor bindings requestName;
      parameters = checkedParameters requests.${requestName}.parameters;
    in {
      inherit requestName binding parameters;
    }) requestNames;
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

  compose = {resources, ...}:
    emptyResult
    // {
      realizations = builtins.mapAttrs (_: resource: {
          schema = "aos.kmod.module-set-realization/v1";
          inherit (resource.value) modules required;
        })
      resources;
    };
in {
  config.aos.abilities.implementations.kernel-modules = {
    inherit provide compose;
  };
}
