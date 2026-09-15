##! Pure provider for the package-owned execution-observer endpoint.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "execution-observer-endpoint";
  declaration = config.aos.abilities.interfaces."${packageName}:${alias}";
  settings = import ./settings.nix {
    socketName = config.aos.services.abilityCrucible.socketName;
  };
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
  entriesFor = context:
    builtins.map
    (requestName: {
      inherit requestName;
      request = context.requests.${requestName};
      bindings =
        builtins.filter
        (binding: binding.request == requestName)
        (builtins.attrValues context.bindings);
    })
    (builtins.attrNames context.requests);
  checkedEntry = entry:
    if builtins.length entry.bindings != 1
    then throw "the Ability Crucible endpoint request requires exactly one selected binding"
    else if entry.request.parameters.endpoint == "default"
    then entry
    else throw "the Ability Crucible endpoint request selects an unknown endpoint";
  provide = context: let
    entries = builtins.map checkedEntry (entriesFor context);
    reference = {
      interface = identity;
      resource = {
        provider = context.instance.id;
        key = "observer";
      };
      operations = ["observe"];
      lifetime = "instance";
    };
  in {
    requests = {};
    resourceFragments = {};
    outputs = builtins.listToAttrs (builtins.map (entry: {
        name = entry.requestName;
        value = {
          retained-resource = reference;
          socket-path = settings.socketPath;
        };
      })
      entries);
  };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide;};
}
