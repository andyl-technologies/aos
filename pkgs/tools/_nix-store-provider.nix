##! Selected pure composition for the Nix store database provider.
{
  config,
  lib,
  ...
}: let
  interfaceAlias = "nix-store-database";
  qualifiedAlias = "aos-nix-store-provider:${interfaceAlias}";
  declaration = config.aos.abilities.interfaces.${qualifiedAlias};
  document = lib.abilities.interfaceDocumentFromDeclaration declaration;
  identity = lib.abilities.interfaceIdentity document;

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
    if builtins.length matches != 1
    then throw "a Nix store database request must have exactly one selected binding"
    else builtins.head matches;
  resourceReference = instance: key: {
    interface = identity;
    resource = {
      provider = instance.id;
      inherit key;
    };
    operations = ["observe"];
    lifetime = "instance";
  };
  checkedParameters = parameters:
    if parameters.scope != "local"
    then throw "the Nix store database provider only supports the local store"
    else parameters;
  provide = {
    instance,
    requests,
    bindings,
    ...
  }: let
    entries = builtins.map (requestName: let
      binding = bindingFor bindings requestName;
      parameters = checkedParameters requests.${requestName}.parameters;
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
          schema = "aos.nix.store-database-realization/v1";
          nix_store = {
            artifact = lib.abilities.packageOutput {package = "nix";};
            entry_point = "bin/nix-store";
            arguments = [];
          };
        })
        resources;
    };
in {
  config.aos.abilities.implementations.${interfaceAlias} = {
    inherit provide compose;
  };
}
