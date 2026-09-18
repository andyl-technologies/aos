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
  projectRequest = name: request: requirement:
    if request.package == null || request.localKey == null
    then throw "source-stage request '${name}' has no package declaration provenance"
    else {
      inherit (request) package consumer scope localKey lifetime parameters;
      inherit requirement;
    };
  projectRootRequest = name: request: let
    requirement =
      abilities.requirementTemplates.${request.requirement}
      or (throw "source-stage request '${name}' references absent package requirement '${request.requirement}'");
  in
    if requirement.package == null || requirement.localKey == null
    then throw "source-stage request '${name}' requirement has no package declaration provenance"
    else if requirement.package != request.package
    then throw "source-stage request '${name}' crosses package requirement provenance"
    else
      projectRequest name request {
        kind = "package";
        inherit (requirement) package localKey;
      };
  projectCompositionRequest = name: request:
    if !(builtins.hasAttr request.requirement abilities.compositionRequirements)
    then throw "source-stage request '${name}' references absent composition requirement '${request.requirement}'"
    else
      projectRequest name request {
        kind = "composition";
        declaration = request.requirement;
      };
  projectBinding = _: binding: {
    inherit (binding) request providerInstance slot;
    implementation = implementationReference "binding implementation" binding.implementation;
  };
  projectCompositionRequirement = _: requirement:
    requirement
    // {
      implementation = implementationReference "composition requirement implementation" requirement.implementation;
    };
in {
  inherit
    (abilities)
    environment
    instanceIdentities
    compositionOutputs
    compositionPendingRequests
    resolvedResources
    ;
  bindings = builtins.mapAttrs projectBinding abilities.bindings;
  compositionRequirements =
    builtins.mapAttrs projectCompositionRequirement abilities.compositionRequirements;
  instances = builtins.mapAttrs projectInstance abilities.instances;
  requests = builtins.mapAttrs projectRootRequest abilities.requests;
  compositionRequests = builtins.mapAttrs projectCompositionRequest abilities.compositionRequests;
  executionObserver = abilities.resolvedExecutionObserver;
}
