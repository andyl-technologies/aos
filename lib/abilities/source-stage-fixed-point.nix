##! Canonical runtime projection of one completed source-stage fixed point.
{abilities}: let
  packageFromDeclaration = context: declaration: let
    matched = builtins.match "([^:]+):.+" declaration;
  in
    if matched == null
    then throw "${context} '${declaration}' is not package-qualified"
    else builtins.head matched;
  unique = values:
    builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = value;
        value = true;
      })
      values));
  allRequests = abilities.requests // abilities.compositionRequests;
  packageForInstance = name: instance: let
    authored =
      if instance.package == null
      then []
      else [instance.package];
    configured =
      if instance.implementation == null
      then []
      else [
        (packageFromDeclaration "instance implementation" instance.implementation)
      ];
    selected = builtins.concatMap (binding:
      if binding.providerInstance == name
      then [(packageFromDeclaration "binding implementation" binding.implementation)]
      else [])
    (builtins.attrValues abilities.bindings);
    consumed = builtins.concatMap (request:
      if request.consumer == name && request.package != null
      then [request.package]
      else [])
    (builtins.attrValues allRequests);
    candidates = unique (authored ++ configured ++ selected ++ consumed);
  in
    if builtins.length candidates == 1
    then builtins.head candidates
    else
      throw
      "source-stage instance '${name}' must resolve exactly one authenticated package owner; candidates: ${builtins.toJSON candidates}";
  projectInstance = name: instance: {
    package = packageForInstance name instance;
    inherit (instance) localKey implementation configuration;
  };
  projectRequest = name: request:
    if request.package == null || request.localKey == null
    then throw "source-stage request '${name}' has no package declaration provenance"
    else {
      inherit (request) package requirement consumer scope localKey lifetime parameters;
    };
in {
  inherit
    (abilities)
    environment
    instanceIdentities
    bindings
    compositionOutputs
    compositionRequirements
    compositionPendingRequests
    resolvedResources
    ;
  instances = builtins.mapAttrs projectInstance abilities.instances;
  requests = builtins.mapAttrs projectRequest abilities.requests;
  compositionRequests = builtins.mapAttrs projectRequest abilities.compositionRequests;
  executionObserver = abilities.resolvedExecutionObserver;
}
