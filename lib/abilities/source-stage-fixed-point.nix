##! Canonical runtime projection of one completed source-stage fixed point.
{abilities}: let
  implementationReference = context: declaration: let
    implementation =
      abilities.implementations.${declaration}
      or (throw "${context} '${declaration}' is absent from the completed fixed point");
  in
    if implementation.package == null || implementation.localKey == null
    then throw "${context} '${declaration}' has no authenticated package provenance"
    else {
      inherit (implementation) package localKey;
    };
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
        (implementationReference "instance implementation" instance.implementation).package
      ];
    selected = builtins.concatMap (binding:
      if binding.providerInstance == name
      then [(implementationReference "binding implementation" binding.implementation).package]
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
    inherit (instance) localKey configuration;
    implementation =
      if instance.implementation == null
      then null
      else implementationReference "instance implementation" instance.implementation;
  };
  projectRequest = name: request:
    if request.package == null || request.localKey == null
    then throw "source-stage request '${name}' has no package declaration provenance"
    else {
      inherit (request) package requirement consumer scope localKey lifetime parameters;
    };
  projectBinding = _: binding: {
    inherit (binding) request providerInstance slot;
    implementation = implementationReference "binding implementation" binding.implementation;
  };
in {
  inherit
    (abilities)
    environment
    instanceIdentities
    compositionOutputs
    compositionRequirements
    compositionPendingRequests
    resolvedResources
    ;
  bindings = builtins.mapAttrs projectBinding abilities.bindings;
  instances = builtins.mapAttrs projectInstance abilities.instances;
  requests = builtins.mapAttrs projectRequest abilities.requests;
  compositionRequests = builtins.mapAttrs projectRequest abilities.compositionRequests;
  executionObserver = abilities.resolvedExecutionObserver;
}
