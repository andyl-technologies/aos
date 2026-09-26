##! Pure provider for the package-owned fleet observation endpoint.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "execution-observer-endpoint";
  declaration = config.aos.abilities.interfaces."${packageName}:${alias}";
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
  checkedEntry = context: let
    entries = entriesFor context;
    entry =
      if builtins.length entries == 1
      then builtins.head entries
      else throw "the fleet observation endpoint requires exactly one request";
    binding =
      if builtins.length entry.bindings == 1
      then builtins.head entry.bindings
      else throw "the fleet observation endpoint requires exactly one selected binding";
    parameters = entry.request.parameters;
    hasServiceResource = (parameters.service_resource or null) != null;
    hostingIsValid =
      if parameters.hosting == "managed-service"
      then hasServiceResource
      else !hasServiceResource;
  in
    if binding.slot != "observer"
    then throw "the fleet observation endpoint accepts only its canonical observer slot, received '${binding.slot}'"
    else if !hostingIsValid
    then throw "the fleet observation endpoint hosting mode does not match its service resource"
    else entry;
  provide = context: let
    entry = checkedEntry context;
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
    outputs.${entry.requestName} = {
      resource = reference;
      socket-path = entry.request.parameters.socket_path;
    };
  };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide;};
}
