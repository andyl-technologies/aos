##! Selected pure composition for the Nix store database provider.
{
  config,
  lib,
  packageName,
  ...
}: let
  interfaceAlias = "nix-store-database";
  qualifiedAlias = "${packageName}:${interfaceAlias}";
  declaration = config.aos.abilities.interfaces.${qualifiedAlias};
  document = lib.abilities.interfaceDocumentFromDeclaration declaration;
  identity = lib.abilities.interfaceIdentity document;
  controller = config.aos.abilities.implementations.${qualifiedAlias};
  effectsInterface = builtins.head controller.requirements.effects.accepted_interfaces;

  emptyResult = {
    conditionalRequirements = [];
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
    lifetime = "persistent";
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
            lifetime = "persistent";
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
  transition = context:
    lib.abilities.resourceControllerTransition {
      inherit context;
      terminalInterface = effectsInterface;
      actions = {
        create = {
          method = "converge";
          phase = "converging";
          access = "exclusive-write";
        };
        update = {
          method = "converge";
          phase = "converging";
          access = "exclusive-write";
        };
        unchanged = null;
        remove = null;
        reconcile-stopped = {
          method = "converge";
          phase = "recovering";
          access = "exclusive-write";
        };
        reconcile-divergent = {
          method = "converge";
          phase = "recovering";
          access = "exclusive-write";
        };
      };
    };
in {
  config.aos.abilities.implementations.${interfaceAlias} = {
    inherit provide compose transition;
  };
}
