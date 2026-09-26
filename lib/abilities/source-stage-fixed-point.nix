##! Canonical runtime projection of one completed source-stage fixed point.
{
  abilities,
  guaranteeIdentity,
  normalizePackageOutputSelectors,
  normalizeRequirement,
  lifetime,
}: let
  normalizeOwnedValue = owner: value:
    if owner == null
    then value
    else normalizePackageOutputSelectors {inherit owner value;};
  declarationOwner = declaration:
    if (declaration.authority.kind or null) == "package"
    then declaration.authority.package
    else null;
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
  projectInstance = name: instance: let
    package = packageForInstance instance;
  in
    {
      provenance = provenanceFor name instance;
      configuration = normalizeOwnedValue (declarationOwner instance) instance.configuration;
      implementation =
        if instance.implementation == null
        then null
        else implementationReference "instance implementation" instance.implementation;
    }
    // (
      if package == null
      then {}
      else {inherit package;}
    );
  resolveRequestValue = requestName: recipientLifetime: trail: value:
    if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then let
      reference = "${value.request}.${value.output}";
      outputs = projectedOutputs.${value.request} or {};
      output = outputs.${value.output} or null;
    in
      if builtins.attrNames value != ["_type" "output" "request"]
      then throw "source-stage request '${requestName}' has a malformed output reference"
      else if output == null
      then throw "source-stage request '${requestName}' references absent planning output '${reference}'"
      else if output.phase != "planning"
      then throw "source-stage request '${requestName}' references non-planning output '${reference}'"
      else if !lifetime.outlivesOrEquals output.lifetime recipientLifetime
      then throw "source-stage request '${requestName}' outlives output '${reference}'"
      else if builtins.elem reference trail
      then throw "source-stage request '${requestName}' has an output cycle through '${reference}'"
      else resolveRequestValue requestName recipientLifetime (trail ++ [reference]) output.value
    else if builtins.isAttrs value
    then builtins.mapAttrs (_: resolveRequestValue requestName recipientLifetime trail) value
    else if builtins.isList value
    then builtins.map (resolveRequestValue requestName recipientLifetime trail) value
    else value;
  projectRequest = name: request: requirement: {
    provenance = provenanceFor name request;
    inherit (request) consumer scope lifetime;
    parameters =
      normalizeOwnedValue
      (declarationOwner request)
      (resolveRequestValue name request.lifetime [] request.parameters);
    inherit requirement;
  };
  projectRootRequest = name: request:
    if !(builtins.hasAttr request.requirement abilities.requirementTemplates)
    then throw "source-stage request '${name}' references absent fixed-point requirement '${request.requirement}'"
    else
      projectRequest name request {
        kind = "fixedPoint";
        declaration = request.requirement;
      };
  projectCompositionRequest = name: request:
    if !(builtins.hasAttr request.requirement abilities.compositionRequirements)
    then throw "source-stage request '${name}' references absent composition requirement '${request.requirement}'"
    else
      (projectRequest name request {
        kind = "composition";
        declaration = request.requirement;
      })
      // (
        if request.ownerRequest == null
        then {}
        else {inherit (request) ownerRequest;}
      );
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
  requestFor = name:
    abilities.requests.${name}
    or abilities.compositionRequests.${name}
    or (throw "source-stage output '${name}' has no request in the completed fixed point");
  projectOutput = requestName: _: output:
    output
    // {
      value = normalizeOwnedValue (declarationOwner (requestFor requestName)) output.value;
    };
  projectedOutputs =
    builtins.mapAttrs
    (requestName: outputs: builtins.mapAttrs (projectOutput requestName) outputs)
    abilities.compositionOutputs;
  projectResolvedResource = name: resource: let
    controller = resource.controller or null;
    binding =
      if controller == null
      then null
      else abilities.bindings.${controller} or null;
    owner =
      if binding == null
      then null
      else (implementationReference "resource '${name}' controller" binding.implementation).package;
    requestName =
      if binding == null
      then "resource '${name}'"
      else binding.request;
  in
    (
      if (resource.revision or null) == null
      then builtins.removeAttrs resource ["revision"]
      else resource
    )
    // {
      value = normalizeOwnedValue owner (resolveRequestValue requestName resource.lifetime [] resource.value);
      realization = normalizeOwnedValue owner (resolveRequestValue requestName resource.lifetime [] resource.realization);
    };
in
  {
    inherit
      (abilities)
      environment
      instanceIdentities
      compositionPendingRequests
      ;
    bindings = builtins.mapAttrs projectBinding abilities.bindings;
    compositionRequirements =
      builtins.mapAttrs projectCompositionRequirement abilities.compositionRequirements;
    requirements = projectedRequirements;
    instances = builtins.mapAttrs projectInstance abilities.instances;
    requests = builtins.mapAttrs projectRootRequest abilities.requests;
    compositionRequests = builtins.mapAttrs projectCompositionRequest abilities.compositionRequests;
    compositionOutputs = projectedOutputs;
    resolvedResources = builtins.mapAttrs projectResolvedResource abilities.resolvedResources;
  }
  // (
    if abilities.resolvedExecutionObserver == null
    then {}
    else {executionObserver = abilities.resolvedExecutionObserver;}
  )
