##! Fixed-point driver for selected pure ability providers.
##!
##! The driver derives provider identities from the canonical instance
##! projection, invokes selected pure constructors, merges compatible resource
##! facets, and attaches the sole write controller's realization.
{
  config,
  lib,
  ...
}: let
  abilities = config.aos.abilities;
  authoredRequests = abilities.requests;

  fail = message: throw "ability composition: ${message}";
  guaranteeFor = reference:
    if builtins.hasAttr reference abilities.guarantees
    then lib.abilities.guaranteeIdentity abilities.guarantees.${reference}
    else fail "guarantee reference '${reference}' has no exact declaration";
  semanticRequirement = requirement:
    requirement // {guarantees = builtins.map guaranteeFor requirement.guarantees;};
  semanticInterface = interface:
    interface
    // {
      guarantees = builtins.map guaranteeFor interface.guarantees;
      methods = builtins.mapAttrs (_: method:
        method // {guarantees = builtins.map guaranteeFor method.guarantees;})
      interface.methods;
    };
  semanticImplementation = implementation:
    implementation
    // {
      guarantees = builtins.map guaranteeFor implementation.guarantees;
      requirements = builtins.mapAttrs (_: semanticRequirement) implementation.requirements;
    };
  semanticInterfaces = builtins.mapAttrs (_: semanticInterface) abilities.interfaces;
  semanticImplementations = builtins.mapAttrs (_: semanticImplementation) abilities.implementations;
  interfaceForImplementation = implementationKey: implementation:
    if builtins.isString implementation.interface
    then semanticInterfaces.${implementation.interface} or (fail "implementation '${implementationKey}' references an absent interface")
    else let
      matches = builtins.filter (declaration:
        lib.abilities.interfaceIdentity (lib.abilities.interfaceDocumentFromDeclaration declaration)
        == implementation.interface)
      (builtins.attrValues semanticInterfaces);
    in
      if builtins.length matches == 1
      then builtins.head matches
      else fail "implementation '${implementationKey}' must resolve its exact shared interface identity to one declaration";
  emptyProvision = {
    conditionalRequirements = [];
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  exactAttrs = context: expected: value: let
    actual = builtins.attrNames value;
  in
    if !builtins.isAttrs value || actual != expected
    then fail "${context} must contain exactly ${builtins.toJSON expected}"
    else value;
  checkedProviderResult = context: implementation: expected: value: let
    result = exactAttrs context expected value;
    active = result.conditionalRequirements;
    unique =
      if builtins.isList active
      then
        builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
            inherit name;
            value = true;
          })
          active))
      else [];
  in
    if
      !builtins.isList active
      || !(builtins.all lib.abilities.types.localKey.check active)
      || builtins.length unique != builtins.length active
      || !(builtins.all (name: builtins.hasAttr name implementation.requirements) active)
    then fail "${context} has invalid conditional requirements"
    else result;

  mergeValue = context: left: right:
    if left == right
    then left
    else if builtins.isAttrs left && builtins.isAttrs right
    then
      builtins.foldl' (merged: name:
        if builtins.hasAttr name merged
        then merged // {${name} = mergeValue "${context}.${name}" merged.${name} right.${name};}
        else merged // {${name} = right.${name};})
      left
      (builtins.attrNames right)
    else fail "${context} has conflicting contributions";

  mergeMaps = context: maps:
    builtins.foldl' (merged: values:
      builtins.foldl' (result: name:
        if builtins.hasAttr name result
        then result // {${name} = mergeValue "${context}.${name}" result.${name} values.${name};}
        else result // {${name} = values.${name};})
      merged
      (builtins.attrNames values))
    {}
    maps;

  groupBy = keyFor: values:
    builtins.foldl' (groups: value: let
      key = keyFor value;
    in
      groups // {${key} = (groups.${key} or []) ++ [value];})
    {}
    values;

  childEntriesForGroups = groups:
    builtins.concatLists (builtins.map (group:
      builtins.map (localRequestKey: let
        authored =
          exactAttrs
          "child request '${localRequestKey}' from '${group.implementationKey}'"
          ["parameters" "requirement" "scope" "slot"]
          group.result.requests.${localRequestKey};
        requirementKey = lib.abilities.compositionRequirementKey {
          implementation = group.implementationKey;
          alias = authored.requirement;
        };
        requestKey = lib.abilities.compositionRequestKey {
          implementation = group.implementationKey;
          inherit (group) providerInstance;
          key = localRequestKey;
        };
      in {
        inherit authored localRequestKey requirementKey;
        originGroup = group.groupKey;
        implementation = group.implementationKey;
        inherit (group) providerInstance;
        requirement = authored.requirement;
        slot = authored.slot;
        request = requestKey;
        declaration = {
          package = null;
          requirement = requirementKey;
          consumer = group.providerInstance;
          inherit (authored) scope parameters;
        };
      }) (builtins.attrNames group.result.requests))
    groups);
  requestMapForChildren = children:
    builtins.listToAttrs (builtins.map (child: {
        name = child.request;
        value = child.declaration;
      })
      children);

  selectedImplementationNames = builtins.attrNames (builtins.listToAttrs (builtins.map (binding: {
      name = binding.implementation;
      value = true;
    })
    (builtins.attrValues abilities.bindings)));
  nestedRequirementEntries = builtins.concatLists (builtins.map (implementationName: let
    implementation = semanticImplementations.${implementationName} or (fail "binding selects absent implementation '${implementationName}'");
  in
    builtins.map (alias: {
      name = lib.abilities.compositionRequirementKey {
        implementation = implementationName;
        inherit alias;
      };
      value = {
        implementation = implementationName;
        inherit alias;
        requirement = implementation.requirements.${alias};
      };
    }) (builtins.attrNames implementation.requirements))
  selectedImplementationNames);
  generatedRequirements = builtins.listToAttrs nestedRequirementEntries;

  requestKeyCollisions = builtins.filter (
    requestName: builtins.hasAttr requestName generatedRequests
  ) (builtins.attrNames authoredRequests);

  selection = bindingName: let
    binding = abilities.bindings.${bindingName};
    request =
      if builtins.hasAttr binding.request authoredRequests
      then authoredRequests.${binding.request}
      else provisionGeneratedRequests.${binding.request}
        or compositionGeneratedRequests.${binding.request}
        or (fail "binding '${bindingName}' selects an absent request");
    implementation = semanticImplementations.${binding.implementation} or (fail "binding '${bindingName}' selects an absent implementation");
    interface = interfaceForImplementation binding.implementation implementation;
    instance = abilities.instances.${binding.providerInstance} or (fail "binding '${bindingName}' selects an absent provider instance");
    provider = abilities.instanceIdentities.${binding.providerInstance} or (fail "binding '${bindingName}' has no canonical provider identity");
  in {
    inherit bindingName binding request implementation interface instance provider;
  };
  selections = builtins.map selection (builtins.attrNames abilities.bindings);
  selectionGroupKey = entry:
    builtins.hashString "sha256" (builtins.toJSON {
      implementation = entry.binding.implementation;
      providerInstance = entry.binding.providerInstance;
    });
  selectionGroups = groupBy selectionGroupKey selections;

  childContextFor = groupKey:
  # Outer resolution rounds add one checked binding and its selected provider
  # module. The derived request remains internal to this fixed point.
    lib.filterAttrs (_: child: child.binding != null) (builtins.mapAttrs (_: child: let
        bindingNames = builtins.filter (
          bindingName: abilities.bindings.${bindingName}.request == child.request
        ) (builtins.attrNames abilities.bindings);
        bindingName =
          if bindingNames == []
          then null
          else if builtins.length bindingNames == 1
          then builtins.head bindingNames
          else fail "provider child request '${child.request}' has several selected bindings";
      in {
        inherit (child) request;
        binding =
          if bindingName == null
          then null
          else bindingName;
        outputs = checkedOutputsForRequest child.request;
      })
      (childGroups.${groupKey}.children or {}));

  contextFor = entries: let
    first = builtins.head entries;
    groupKey = selectionGroupKey first;
  in {
    provider = first.provider;
    instance = {
      id = first.provider;
      configuration = first.instance.configuration;
    };
    requests = builtins.listToAttrs (builtins.map (entry: {
        name = entry.binding.request;
        value = entry.request;
      })
      entries);
    bindings = builtins.listToAttrs (builtins.map (entry: {
        name = entry.bindingName;
        value = entry.binding;
      })
      entries);
    children = childContextFor groupKey;
  };

  provisionGroup = entries: let
    first = builtins.head entries;
    groupKey = selectionGroupKey first;
    slots = builtins.map (entry: entry.binding.slot) entries;
    uniqueSlots = builtins.attrNames (builtins.listToAttrs (builtins.map (slot: {
        name = slot;
        value = true;
      })
      slots));
    authored =
      if first.implementation.provide == null
      then emptyProvision
      else first.implementation.provide (contextFor entries);
    result =
      checkedProviderResult
      "provide result for '${first.binding.implementation}'"
      first.implementation
      ["conditionalRequirements" "outputs" "requests" "resourceFragments"]
      authored;
  in
    if first.interface.aggregation.rejectSlotCollisions && builtins.length slots != builtins.length uniqueSlots
    then fail "implementation '${first.binding.implementation}' received duplicate aggregation slots"
    else {
      inherit entries groupKey result;
      context = contextFor entries;
      implementationKey = first.binding.implementation;
      providerInstance = first.binding.providerInstance;
      inherit (first) implementation interface provider;
    };
  provisionGroups = builtins.map provisionGroup (builtins.attrValues selectionGroups);
  provisionChildEntries = childEntriesForGroups provisionGroups;
  provisionGeneratedRequests = requestMapForChildren provisionChildEntries;

  fragmentEntries = builtins.concatLists (builtins.map (group:
    builtins.map (key: let
      fragment =
        exactAttrs
        "resource fragment '${key}' from '${group.implementationKey}'"
        ["kind" "lifetime" "value"]
        group.result.resourceFragments.${key};
      matchingBindings = builtins.filter (entry: entry.binding.slot == key) group.entries;
    in
      if matchingBindings == []
      then fail "resource fragment '${key}' does not match a selected binding slot"
      else {
        inherit key fragment group matchingBindings;
        resource = {
          provider = group.provider;
          inherit key;
        };
        aggregation = group.interface.aggregation;
      })
    (builtins.attrNames group.result.resourceFragments))
  provisionGroups);
  fragmentsByResource = groupBy (entry: builtins.hashString "sha256" (builtins.toJSON entry.resource)) fragmentEntries;

  controlsKind = kind: entry:
    builtins.any (methodName: let
      method = entry.interface.methods.${methodName} or null;
    in
      method
      != null
      && method.targetResource == kind
      && method.semantics.requiredTargetAccess == "exclusive-write")
    entry.implementation.methods;

  mergeResource = entries: let
    first = builtins.head entries;
    aggregations = builtins.map (entry: entry.aggregation) entries;
    compatible = builtins.all (aggregation:
      aggregation.scope
      == "provider-instance"
      && aggregation.controllerGroup == first.aggregation.controllerGroup
      && aggregation.mergeContract == first.aggregation.mergeContract)
    aggregations;
    values = builtins.map (entry: entry.fragment.value) entries;
    kinds = builtins.map (entry: entry.fragment.kind) entries;
    lifetimes = builtins.map (entry: entry.fragment.lifetime) entries;
    controllerCandidates =
      builtins.filter
      (entry:
        entry.provider
        == first.resource.provider
        && entry.implementation.compose != null
        && entry.binding.slot == first.key
        && entry.interface.aggregation.controllerGroup == first.aggregation.controllerGroup
        && controlsKind first.fragment.kind entry)
      selections;
  in
    if !compatible
    then fail "resource '${builtins.toJSON first.resource}' has incompatible aggregation contracts"
    else if builtins.length entries > 1 && first.aggregation.mergeContract == null
    then fail "resource '${builtins.toJSON first.resource}' has several fragments without a merge contract"
    else if !(builtins.all (kind: kind == first.fragment.kind) kinds)
    then fail "resource '${builtins.toJSON first.resource}' has conflicting kinds"
    else if !(builtins.all (lifetime: lifetime == first.fragment.lifetime) lifetimes)
    then fail "resource '${builtins.toJSON first.resource}' has conflicting lifetimes"
    else if builtins.length controllerCandidates != 1
    then fail "resource '${builtins.toJSON first.resource}' must have exactly one selected exclusive-write controller"
    else {
      inherit (first) resource;
      kind = first.fragment.kind;
      lifetime = first.fragment.lifetime;
      value = mergeMaps "resource '${first.key}'" values;
      controller = builtins.head controllerCandidates;
    };
  mergedResources = builtins.map mergeResource (builtins.attrValues fragmentsByResource);
  publishedPlanningResources = builtins.concatLists (builtins.map (group:
    builtins.concatLists (builtins.map (requestName:
      builtins.concatMap (outputName: let
        value = group.result.outputs.${requestName}.${outputName};
      in
        lib.optional
        (lib.abilities.types.resourceReference.check value
          && !builtins.any (resource: resource.resource == value.resource) mergedResources) {
          inherit (value) resource lifetime;
          kind = value.interface.name;
          value = group.context.requests.${requestName}.parameters;
          controller = null;
        })
      (builtins.attrNames group.result.outputs.${requestName}))
    (builtins.attrNames group.result.outputs)))
  provisionGroups);
  plannedResources = mergedResources ++ publishedPlanningResources;
  resourcesByController = groupBy (resource:
    builtins.hashString "sha256" (builtins.toJSON {
      implementation = resource.controller.binding.implementation;
      providerInstance = resource.controller.binding.providerInstance;
    }))
  mergedResources;

  composeGroup = resources: let
    controller = (builtins.head resources).controller;
    groupKey = selectionGroupKey controller;
    provision = selectionGroups.${groupKey};
    resourceMap = builtins.listToAttrs (builtins.map (resource: {
        name = resource.resource.key;
        value = builtins.removeAttrs resource ["controller"];
      })
      resources);
    authored =
      if controller.implementation.compose == null
      then fail "controller '${controller.binding.implementation}' has no selected compose constructor"
      else
        controller.implementation.compose ((contextFor provision)
          // {
            resources = resourceMap;
            allResources = plannedResources;
          });
    result =
      checkedProviderResult
      "compose result for '${controller.binding.implementation}'"
      controller.implementation
      ["conditionalRequirements" "outputs" "realizations" "requests"]
      authored;
  in
    if builtins.attrNames result.realizations != builtins.attrNames resourceMap
    then fail "controller '${controller.binding.implementation}' did not realize exactly its supplied resources"
    else {
      inherit groupKey resources result;
      context = contextFor provision;
      entries = provision;
      implementationKey = controller.binding.implementation;
      providerInstance = controller.binding.providerInstance;
      inherit (controller) implementation provider;
    };
  compositionGroups = builtins.map composeGroup (builtins.attrValues resourcesByController);

  resultGroups = provisionGroups ++ compositionGroups;
  compositionChildEntries = childEntriesForGroups compositionGroups;
  compositionGeneratedRequests = requestMapForChildren compositionChildEntries;
  childEntries = provisionChildEntries ++ compositionChildEntries;
  childrenByRequest = groupBy (child: child.request) childEntries;
  childRequestKeysUnique = builtins.all (children: builtins.length children == 1) (
    builtins.attrValues childrenByRequest
  );
  generatedRequests =
    if !childRequestKeysUnique
    then fail "every derived child request key must have exactly one producer"
    else builtins.mapAttrs (_: children: (builtins.head children).declaration) childrenByRequest;
  childrenByOrigin = groupBy (child: child.originGroup) childEntries;
  childGroups =
    builtins.mapAttrs (_: children: {
      children = builtins.listToAttrs (builtins.map (child: {
          name = child.localRequestKey;
          value = child;
        })
        children);
    })
    childrenByOrigin;
  childDeclarationsValid = builtins.all (child: let
    implementation = semanticImplementations.${child.implementation};
    requirement = implementation.requirements.${child.requirement} or null;
    acceptedDeclarations =
      if requirement == null
      then []
      else
        builtins.filter (interface: let
          identity = lib.abilities.interfaceIdentity (
            lib.abilities.interfaceDocumentFromDeclaration interface
          );
        in
          builtins.any
          (selector: lib.abilities.interfaceSelectorMatches selector identity)
          requirement.accepted_interfaces)
        (builtins.attrValues semanticInterfaces);
  in
    lib.abilities.types.localKey.check child.localRequestKey
    && lib.abilities.types.localKey.check child.requirement
    && builtins.all lib.abilities.types.localKey.check child.authored.scope
    && requirement != null
    && builtins.any (interface: interface.requestType.check child.authored.parameters) acceptedDeclarations)
  childEntries;
  childBindingsValid =
    builtins.all (
      child: builtins.length (bindingNamesForRequest child.request) <= 1
    )
    childEntries;
  internalBindingsValid = builtins.all (entry:
    if builtins.hasAttr entry.binding.request authoredRequests
    then true
    else let
      internalRequirement = generatedRequirements.${entry.request.requirement} or null;
      interfaceIdentity = lib.abilities.interfaceIdentity (
        lib.abilities.interfaceDocumentFromDeclaration entry.interface
      );
    in
      internalRequirement
      != null
      && builtins.any
      (selector: lib.abilities.interfaceSelectorMatches selector interfaceIdentity)
      internalRequirement.requirement.accepted_interfaces
      && builtins.all (method: builtins.elem method entry.implementation.methods) internalRequirement.requirement.methods
      && builtins.all (guarantee: builtins.elem guarantee entry.implementation.guarantees) internalRequirement.requirement.guarantees
      && entry.interface.requestType.check entry.request.parameters)
  selections;

  desiredResources = builtins.listToAttrs (builtins.concatLists (builtins.map (composition:
    builtins.map (resource: {
      name = "resource-${builtins.hashString "sha256" (builtins.toJSON resource.resource)}";
      value = {
        inherit (resource) resource kind lifetime value;
        controller = resource.controller.bindingName;
        realization = composition.result.realizations.${resource.resource.key};
      };
    })
    composition.resources)
  compositionGroups));

  outputFor = group: requestName: outputName: value: let
    request = group.context.requests.${requestName} or (fail "provider output references an unselected request '${requestName}'");
    selectionsForRequest =
      builtins.filter (
        entry: entry.binding.request == requestName
      )
      group.entries;
    declaration =
      if builtins.length selectionsForRequest == 1
      then (builtins.head selectionsForRequest).interface
      else fail "request '${requestName}' does not resolve one exact output interface";
    descriptor = declaration.outputs.${outputName} or (fail "provider returned undeclared output '${outputName}' for '${requestName}'");
  in
    if descriptor.phase != "planning"
    then fail "pure provider emitted non-planning output '${requestName}.${outputName}'"
    else if !(lib.abilities.types.deferredResult descriptor.schema).check value
    then fail "provider output '${requestName}.${outputName}' does not match its declared type"
    else {
      inherit value;
      inherit (descriptor) phase visibility lifetime;
    };
  checkedOutputsForRequest = requestName: let
    matchingSelections =
      builtins.filter (
        entry: entry.binding.request == requestName
      )
      selections;
    selectedInterface =
      if builtins.length matchingSelections == 1
      then (builtins.head matchingSelections).interface
      else fail "provider child request '${requestName}' must have one exact selected binding";
    expectedNames = builtins.filter (
      outputName: selectedInterface.outputs.${outputName}.phase == "planning"
    ) (builtins.attrNames selectedInterface.outputs);
    matchingGroups =
      builtins.filter (
        group: builtins.hasAttr requestName group.context.requests
      )
      resultGroups;
    entries = builtins.concatLists (builtins.map (group:
      if builtins.hasAttr requestName group.result.outputs
      then
        builtins.map (outputName: {
          name = outputName;
          value = outputFor group requestName outputName group.result.outputs.${requestName}.${outputName};
        }) (builtins.attrNames group.result.outputs.${requestName})
      else [])
    matchingGroups);
    byName = groupBy (entry: entry.name) entries;
    valid =
      builtins.attrNames byName
      == expectedNames
      && builtins.all (values: builtins.length values == 1) (builtins.attrValues byName);
  in
    if !valid
    then fail "provider child request '${requestName}' must expose every planning output exactly once"
    else builtins.mapAttrs (_: values: (builtins.head values).value) byName;
  expectedOutputEntries = builtins.concatLists (builtins.map (entry:
    builtins.map (outputName: {
      key = builtins.hashString "sha256" (builtins.toJSON {
        request = entry.binding.request;
        output = outputName;
      });
      requestName = entry.binding.request;
      inherit outputName;
    })
    (builtins.filter (
      outputName: entry.interface.outputs.${outputName}.phase == "planning"
    ) (builtins.attrNames entry.interface.outputs)))
  selections);
  expectedOutputs = builtins.listToAttrs (builtins.map (entry: {
      name = entry.key;
      value = entry;
    })
    expectedOutputEntries);
  actualOutputEntries = builtins.concatLists (builtins.map (group:
    builtins.concatLists (builtins.map (requestName:
      builtins.map (outputName: {
        key = builtins.hashString "sha256" (builtins.toJSON {
          request = requestName;
          output = outputName;
        });
        inherit requestName outputName;
        output = outputFor group requestName outputName group.result.outputs.${requestName}.${outputName};
      })
      (builtins.attrNames group.result.outputs.${requestName}))
    (builtins.attrNames group.result.outputs)))
  resultGroups);
  actualOutputsByKey = groupBy (entry: entry.key) actualOutputEntries;
  outputSetValid =
    builtins.attrNames actualOutputsByKey
    == builtins.attrNames expectedOutputs
    && builtins.all (entries: builtins.length entries == 1) (builtins.attrValues actualOutputsByKey);
  compositionOutputs =
    builtins.foldl' (outputs: entry:
      outputs
      // {
        ${entry.requestName} = (outputs.${entry.requestName} or {}) // {${entry.outputName} = entry.output;};
      })
    {}
    actualOutputEntries;
  bindingNamesForRequest = requestKey:
    builtins.filter (
      bindingName: abilities.bindings.${bindingName}.request == requestKey
    ) (builtins.attrNames abilities.bindings);
  unresolvedChildren =
    builtins.filter (
      child: bindingNamesForRequest child.request == []
    )
    childEntries;
  pendingRequests =
    if !childRequestKeysUnique
    then fail "every derived child request key must have exactly one producer"
    else
      builtins.listToAttrs (builtins.map (child: {
          name = child.request;
          value = {
            inherit (child) originGroup localRequestKey implementation providerInstance requirement request slot declaration;
          };
        })
        unresolvedChildren);
  unresolvedByOrigin = groupBy (child: child.originGroup) unresolvedChildren;
  pendingRequirements =
    builtins.mapAttrs (_: children: let
      first = builtins.head children;
    in {
      inherit (first) implementation providerInstance;
      requirements = builtins.attrNames (builtins.listToAttrs (builtins.map (child: {
          name = child.requirement;
          value = true;
        })
        children));
    })
    unresolvedByOrigin;
  noUnboundComposition = pendingRequests == {};
in {
  config.aos.abilities.compositionRequests = generatedRequests;
  config.aos.abilities.compositionRequirements = generatedRequirements;
  config.aos.abilities.compositionPendingRequests = pendingRequests;
  config.aos.abilities.compositionPendingRequirements = pendingRequirements;

  config.aos.abilities.compositionOutputs =
    if requestKeyCollisions != []
    then fail "authored requests collide with derived provider child requests"
    else if !childRequestKeysUnique
    then fail "every derived child request key must have exactly one producer"
    else if !childDeclarationsValid
    then fail "a provider child request does not match its nested implementation requirement"
    else if !childBindingsValid
    then fail "a provider child request has several selected bindings"
    else if !internalBindingsValid
    then fail "a selected child binding does not satisfy its generated requirement"
    else if !noUnboundComposition
    then fail "fixed-point provider child requests need a selected binding projection"
    else if !outputSetValid
    then fail "selected providers must produce every declared output exactly once"
    else compositionOutputs;

  config.aos.abilities.desiredResources =
    if requestKeyCollisions != []
    then fail "authored requests collide with derived provider child requests"
    else if !childRequestKeysUnique
    then fail "every derived child request key must have exactly one producer"
    else if !childDeclarationsValid
    then fail "a provider child request does not match its nested implementation requirement"
    else if !childBindingsValid
    then fail "a provider child request has several selected bindings"
    else if !internalBindingsValid
    then fail "a selected child binding does not satisfy its generated requirement"
    else if !noUnboundComposition
    then fail "fixed-point provider child requests need a selected binding projection"
    else if !outputSetValid
    then fail "selected providers must produce every declared output exactly once"
    else desiredResources;
}
