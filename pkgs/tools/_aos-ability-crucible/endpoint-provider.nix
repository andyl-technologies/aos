##! Pure Crucible provider for the execution-observation endpoint.
{
  config,
  lib,
  ...
}: let
  endpoint = lib.abilities.interfaces.executionObservationEndpoint.interfaces.endpoint;
  settings = import ./settings.nix {
    socketName = config.aos.services.abilityCrucible.socketName;
  };
  identity = endpoint.identity;
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
    referenceFor = entry: {
      _type = "aos-resource-reference";
      interface = identity;
      resource = {
        provider = context.instance.id;
        key = (builtins.head entry.bindings).slot;
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
          resource = referenceFor entry;
          socket-path = settings.socketPath;
        };
      })
      entries);
  };
in {
  config.aos.abilities.implementations.${endpoint.alias} = {inherit provide;};
}
