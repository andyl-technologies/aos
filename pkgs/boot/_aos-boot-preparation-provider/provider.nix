##! Pure resource composition for transaction-scoped boot preparations.
{lib, ...}: let
  interface = lib.abilities.interfaces.bootPreparation.interfaces.preparation;
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a boot-preparation request must have exactly one selected binding";
  resourceReference = instance: key: {
    interface = interface.identity;
    resource = {
      provider = instance.id;
      inherit key;
    };
    operations = ["observe"];
    lifetime = "transaction";
  };
  provide = {
    instance,
    requests,
    bindings,
    ...
  }: let
    entries = builtins.map (requestName: {
      inherit requestName;
      request = requests.${requestName};
      binding = bindingFor bindings requestName;
    }) (builtins.attrNames requests);
  in
    emptyProvision
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
        name = entry.requestName;
        value.preparation-resource = resourceReference instance entry.binding.slot;
      }) entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
        name = entry.binding.slot;
        value = {
          kind = interface.name;
          lifetime = "transaction";
          value = entry.request.parameters;
        };
      }) entries);
    };
  compose = {resources, ...}: {
    requests = {};
    outputs = {};
    realizations = builtins.mapAttrs (_: _: {
      schema = "aos.boot.preparation-realization/v1";
    }) resources;
  };
in {
  config.aos.abilities.implementations.boot-preparation = {
    inherit provide compose;
  };
}
