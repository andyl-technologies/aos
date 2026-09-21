##! Canonical runtime projection of one completed source-stage fixed point.
{
  abilities,
  guaranteeIdentity,
  normalizeRequirement,
}: let
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
  provenanceFor = context: declaration: let
    localKey = declaration.localKey or null;
    inferredLocalKey =
      if localKey != null
      then localKey
      else throw "source-stage declaration '${context}' has no local key";
  in {
    inherit (declaration) authority;
    localKey = inferredLocalKey;
  };
  packageForInstance = instance:
    if instance.implementation != null
    then (implementationReference "instance implementation" instance.implementation).package
    else null;
  projectInstance = name: instance: {
    provenance = provenanceFor name instance;
    package = packageForInstance instance;
    inherit (instance) configuration;
    implementation =
      if instance.implementation == null
      then null
      else implementationReference "instance implementation" instance.implementation;
  };
  projectRequest = name: request: requirement: {
    provenance = provenanceFor name request;
    inherit (request) consumer scope lifetime parameters;
    inherit requirement;
  };
  projectRootRequest = name: request:
    if !(builtins.hasAttr request.requirement abilities.requirementTemplates)
    then throw "source-stage request '${name}' references absent fixed-point requirement '${request.requirement}'"
    else
      projectRequest name request {
        kind = "fixed-point";
        declaration = request.requirement;
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
  semanticRequirement = name: requirement: let
    guaranteeFor = reference:
      if builtins.hasAttr reference abilities.guarantees
      then guaranteeIdentity (builtins.removeAttrs abilities.guarantees.${reference} ["package" "localKey"])
      else throw "source-stage requirement '${name}' references absent guarantee '${reference}'";
    value =
      builtins.removeAttrs requirement ["package" "localKey"]
      // {guarantees = builtins.map guaranteeFor requirement.guarantees;};
  in
    normalizeRequirement requirement.localKey value;
  referencedRootRequirements = builtins.attrNames (builtins.listToAttrs (builtins.map (request: {
      name = request.requirement;
      value = true;
    })
    (builtins.attrValues abilities.requests)));
  projectedRequirements = builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = semanticRequirement name abilities.requirementTemplates.${name};
    })
    referencedRootRequirements);
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
  requirements = projectedRequirements;
  instances = builtins.mapAttrs projectInstance abilities.instances;
  requests = builtins.mapAttrs projectRootRequest abilities.requests;
  compositionRequests = builtins.mapAttrs projectCompositionRequest abilities.compositionRequests;
  executionObserver = abilities.resolvedExecutionObserver;
}
