##! Selected pure composition for kernel-tunable convergence.
{lib, ...}: let
  alias = "kernel-tunables";
  interface = lib.abilities.interfaces.kernelTunables.interface;
  identity = interface.identity;
  emptyResult = {
    requests = {};
    outputs = {};
  };
  bindingFor = bindings: requestName: let
    matches =
      builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a kernel-tunable request must have exactly one selected binding";
  resourceReference = instance: key: {
    interface = identity;
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
      parameters = requests.${requestName}.parameters;
    in {
      inherit requestName binding parameters;
    }) (builtins.attrNames requests);
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
            kind = identity.name;
            lifetime = "instance";
            value = entry.parameters;
          };
        })
        entries);
    };
  compose = {resources, ...}:
    emptyResult
    // {
      realizations =
        builtins.mapAttrs (_: _: {
          schema = "aos.kernel.tunables-realization/v1";
        })
        resources;
    };
in {
  config.aos.abilities.implementations.${alias} = {
    inherit provide compose;
  };
}
