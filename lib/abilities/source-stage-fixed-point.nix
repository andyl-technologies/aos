##! Canonical runtime projection of one completed source-stage fixed point.
{
  abilities,
  guaranteeIdentity,
  normalizePackageOutputSelectors,
  normalizeRequirement,
  lifetime,
  interfaceIdentity,
  interfaceDocumentFromDeclaration,
  requestOutputDescriptor,
  semanticInterface,
  canonicalizeResolvedValue,
}: let
  filterAttrs = predicate: values:
    builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = values.${name};
      })
      (builtins.filter (name: predicate name values.${name}) (builtins.attrNames values)));
  # Package runtime contracts omit build-only implementations, so their
  # bindings and dependent declarations cannot enter the executable stage.
  retainedBindings = filterAttrs (_: binding:
    abilities.implementations.${binding.implementation}.activationAvailable)
  abilities.bindings;
  omittedBindings = filterAttrs (name: _: !(builtins.hasAttr name retainedBindings)) abilities.bindings;
  retainedRequestNames = builtins.map (binding: binding.request) (builtins.attrValues retainedBindings);
  retainedRequests = filterAttrs (name: _: builtins.elem name retainedRequestNames) abilities.requests;
  retainedCompositionRequests =
    filterAttrs (name: _: builtins.elem name retainedRequestNames) abilities.compositionRequests;
  omittedRequests = filterAttrs (name: _: !(builtins.elem name retainedRequestNames)) abilities.requests;
  omittedCompositionRequests =
    filterAttrs (name: _: !(builtins.elem name retainedRequestNames)) abilities.compositionRequests;
  retainedActorNames =
    builtins.map (binding: binding.providerInstance) (builtins.attrValues retainedBindings)
    ++ builtins.map (request: request.consumer)
    (builtins.attrValues retainedRequests ++ builtins.attrValues retainedCompositionRequests);
  omittedActorNames =
    builtins.map (binding: binding.providerInstance) (builtins.attrValues omittedBindings)
    ++ builtins.map (request: request.consumer)
    (builtins.attrValues omittedRequests ++ builtins.attrValues omittedCompositionRequests);
  retainedInstances = filterAttrs (name: _:
    !(builtins.elem name omittedActorNames) || builtins.elem name retainedActorNames)
  abilities.instances;
  retainedInstanceIdentities =
    filterAttrs (name: _: builtins.hasAttr name retainedInstances) abilities.instanceIdentities;
  retainedCompositionRequirements = filterAttrs (name: _:
    builtins.any (request: request.requirement == name)
    (builtins.attrValues retainedCompositionRequests))
  abilities.compositionRequirements;
  retainedCompositionOutputs =
    filterAttrs (name: _: builtins.elem name retainedRequestNames) abilities.compositionOutputs;
  retainedResources = filterAttrs (_: resource:
    (resource.controller or null)
    == null
    || builtins.hasAttr resource.controller retainedBindings)
  abilities.resolvedResources;

  normalizeOwnedValue = owner: value:
    if owner == null
    then value
    else normalizePackageOutputSelectors {inherit owner value;};
  declarationOwner = declaration:
    if (declaration.authority.kind or null) == "package"
    then declaration.authority.package
    else null;
  guaranteeFor = reference:
    if builtins.hasAttr reference abilities.guarantees
    then guaranteeIdentity abilities.guarantees.${reference}
    else throw "source-stage output references absent guarantee '${reference}'";
  semanticInterfaces = builtins.mapAttrs (_: candidate:
    semanticInterface {
      interface = candidate;
      inherit guaranteeFor;
    })
  abilities.interfaces;
  interfacesByIdentity =
    builtins.foldl' (indexed: candidate: let
      identity = builtins.toJSON (interfaceIdentity (interfaceDocumentFromDeclaration candidate));
    in
      indexed // {${identity} = (indexed.${identity} or []) ++ [candidate];})
    {}
    (builtins.attrValues semanticInterfaces);
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
  selectedInterface = context: implementation:
    if builtins.isString implementation.interface
    then semanticInterfaces.${implementation.interface}
      or (throw "${context} selects absent interface '${implementation.interface}'")
    else let
      identity = builtins.toJSON implementation.interface;
      matchingInterfaces = interfacesByIdentity.${identity} or [];
    in
      if builtins.length matchingInterfaces == 1
      then builtins.head matchingInterfaces
      else throw "${context} has no exact interface declaration";
  requestTypeFor = name: let
    binding = bindingsByRequest.${name}
      or (throw "source-stage request '${name}' has no selected binding");
    implementation = abilities.implementations.${binding.implementation}
      or (throw "source-stage request '${name}' selects an absent implementation");
  in
    (selectedInterface "source-stage request '${name}'" implementation).requestType;
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
  # Generated provider instances can be system-authored. Their package pin
  # comes from the exact selected implementation, not declaration authority.
  selectedPackagesByInstance =
    builtins.foldl' (packages: binding: let
      package = (implementationReference "binding implementation" binding.implementation).package;
      prior = packages.${binding.providerInstance} or null;
    in
      if prior != null && prior != package
      then throw "source-stage provider instance '${binding.providerInstance}' selects implementations from different packages"
      else packages // {${binding.providerInstance} = package;})
    {}
    (builtins.attrValues retainedBindings);
  packageForInstance = name: instance: let
    selected = selectedPackagesByInstance.${name} or null;
    declared =
      if instance.implementation != null
      then (implementationReference "instance implementation" instance.implementation).package
      else null;
  in
    if selected != null && declared != null && selected != declared
    then throw "source-stage provider instance '${name}' has conflicting package provenance"
    else if declared != null
    then declared
    else selected;
  projectInstance = name: instance: let
    package = packageForInstance name instance;
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
  outputDescriptorFor = requestName: outputName: let
    binding = bindingsByRequest.${requestName}
      or (throw "source-stage output '${requestName}.${outputName}' needs one selected binding");
    implementation = abilities.implementations.${binding.implementation}
      or (throw "source-stage output selects absent implementation '${binding.implementation}'");
    interface = selectedInterface "source-stage output '${requestName}.${outputName}'" implementation;
    request = abilities.requests.${requestName}
      or abilities.compositionRequests.${requestName}
      or (throw "source-stage output '${requestName}.${outputName}' has no exact request");
    requirement = abilities.requirementTemplates.${request.requirement}
      or (abilities.compositionRequirements.${request.requirement}.requirement
        or (throw "source-stage output '${requestName}.${outputName}' has no exact requirement"));
  in
    requestOutputDescriptor {
      inherit interface outputName;
      methods = requirement.methods;
      context = "source-stage output '${requestName}.${outputName}'";
    };
  resolveRequestValue = requestName: recipientLifetime: trail: value:
    if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then let
      reference = "${value.request}.${value.output}";
      descriptor = outputDescriptorFor value.request value.output;
      outputs = projectedOutputs.${value.request} or {};
      output = outputs.${value.output} or null;
    in
      if builtins.attrNames value != ["_type" "output" "request"]
      then throw "source-stage request '${requestName}' has a malformed output reference"
      else if !lifetime.outlivesOrEquals descriptor.lifetime recipientLifetime
      then throw "source-stage request '${requestName}' outlives output '${reference}'"
      else if descriptor.phase == "runtime"
      then value
      else if descriptor.phase != "planning"
      then throw "source-stage request '${requestName}' references unsupported output phase '${reference}'"
      else if output == null
      then throw "source-stage request '${requestName}' references absent planning output '${reference}'"
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
      canonicalizeResolvedValue
      "source-stage request '${name}'"
      (requestTypeFor name)
      (normalizeOwnedValue
        (declarationOwner request)
        (resolveRequestValue name request.lifetime [] request.parameters));
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
  bindingEntries = builtins.map (binding: {
    name = binding.request;
    value = binding;
  }) (builtins.attrValues retainedBindings);
  bindingsByRequest = let
    selected = builtins.listToAttrs bindingEntries;
  in
    if builtins.length (builtins.attrNames selected) != builtins.length bindingEntries
    then throw "source-stage output has several selected bindings for one request"
    else selected;
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
    (builtins.attrValues retainedRequests)));
  projectedRequirements = builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = semanticRequirement name abilities.requirementTemplates.${name};
    })
    referencedRootRequirements);
  projectOutput = requestName: _: output: let
    binding = bindingsByRequest.${requestName}
      or (throw "source-stage output '${requestName}' has no selected binding");
    owner = (implementationReference "output provider" binding.implementation).package;
  in
    output // {value = normalizeOwnedValue owner output.value;};
  projectedOutputs =
    builtins.mapAttrs
    (requestName: outputs: builtins.mapAttrs (projectOutput requestName) outputs)
    retainedCompositionOutputs;
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
    desiredType =
      if binding == null
      then null
      else abilities.implementations.${binding.implementation}.desiredType;
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
      realization =
        if desiredType == null
        then normalizeOwnedValue owner (resolveRequestValue requestName resource.lifetime [] resource.realization)
        else
          canonicalizeResolvedValue
          "source-stage resource '${name}' realization"
          desiredType
          (normalizeOwnedValue owner (resolveRequestValue requestName resource.lifetime [] resource.realization));
    };
in
  {
    inherit
      (abilities)
      environment
      compositionPendingRequests
      ;
    instanceIdentities = retainedInstanceIdentities;
    bindings = builtins.mapAttrs projectBinding retainedBindings;
    compositionRequirements =
      builtins.mapAttrs projectCompositionRequirement retainedCompositionRequirements;
    requirements = projectedRequirements;
    instances = builtins.mapAttrs projectInstance retainedInstances;
    requests = builtins.mapAttrs projectRootRequest retainedRequests;
    compositionRequests = builtins.mapAttrs projectCompositionRequest retainedCompositionRequests;
    compositionOutputs = projectedOutputs;
    resolvedResources = builtins.mapAttrs projectResolvedResource retainedResources;
  }
  // (
    if abilities.resolvedExecutionObserver == null
    then {}
    else {executionObserver = abilities.resolvedExecutionObserver;}
  )
