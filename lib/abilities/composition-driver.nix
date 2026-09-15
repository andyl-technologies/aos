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

  fail = message: throw "ability composition: ${message}";
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
    conditionalRequirements = [];
  };
  exactAttrs = context: expected: value: let
    actual = builtins.attrNames value;
  in
    if !builtins.isAttrs value || actual != expected
    then fail "${context} must contain exactly ${builtins.toJSON expected}"
    else value;

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

  selection = bindingName: let
    binding = abilities.bindings.${bindingName};
    request = abilities.requests.${binding.request} or (fail "binding '${bindingName}' selects an absent request");
    implementation = abilities.implementations.${binding.implementation} or (fail "binding '${bindingName}' selects an absent implementation");
    interface = abilities.interfaces.${implementation.interface} or (fail "implementation '${binding.implementation}' references an absent interface");
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

  contextFor = entries: let
    first = builtins.head entries;
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
      exactAttrs
      "provide result for '${first.binding.implementation}'"
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

  requestedMethods = entry:
    abilities.requirementTemplates.${entry.request.requirement}.methods;
  controlsKind = kind: entry:
    builtins.any (methodName: let
      method = entry.interface.methods.${methodName} or null;
    in
      method
      != null
      && method.targetResource == kind
      && method.semantics.requiredTargetAccess == "exclusive-write")
    (requestedMethods entry);

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
      else controller.implementation.compose ((contextFor provision) // {resources = resourceMap;});
    result =
      exactAttrs
      "compose result for '${controller.binding.implementation}'"
      ["conditionalRequirements" "outputs" "realizations" "requests"]
      authored;
  in
    if builtins.attrNames result.realizations != builtins.attrNames resourceMap
    then fail "controller '${controller.binding.implementation}' did not realize exactly its supplied resources"
    else {
      inherit groupKey resources result;
      context = contextFor provision;
      implementationKey = controller.binding.implementation;
      providerInstance = controller.binding.providerInstance;
      inherit (controller) implementation provider;
    };
  compositionGroups = builtins.map composeGroup (builtins.attrValues resourcesByController);

  resultGroups = provisionGroups ++ compositionGroups;
  pendingRequestEntries = builtins.concatLists (builtins.map (group:
    builtins.map (name: {
      inherit name;
      value = group.result.requests.${name};
    }) (builtins.attrNames group.result.requests))
  resultGroups);
  pendingRequestsByKey = groupBy (entry: entry.name) pendingRequestEntries;
  pendingRequestSetValid = builtins.all (entries: builtins.length entries == 1) (
    builtins.attrValues pendingRequestsByKey
  );
  pendingRequests =
    if !pendingRequestSetValid
    then fail "every provider child request key must have exactly one producer"
    else builtins.mapAttrs (_: entries: (builtins.head entries).value) pendingRequestsByKey;
  pendingRequirementGroups = groupBy (group: group.groupKey) resultGroups;
  checkedPendingRequirementGroup = groups: let
    first = builtins.head groups;
    aliases = builtins.concatLists (builtins.map (group: group.result.conditionalRequirements) groups);
    canonicalAliases = builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = true;
      })
      aliases));
    declaredAliases = builtins.attrNames first.implementation.requirements;
    sameSelection = builtins.all (group:
      group.implementationKey
      == first.implementationKey
      && group.providerInstance == first.providerInstance)
    groups;
    unknownAliases = builtins.filter (name: !(builtins.elem name declaredAliases)) aliases;
  in
    if !sameSelection
    then fail "conditional requirements crossed an implementation/provider selection group"
    else if aliases != canonicalAliases
    then fail "conditional requirements for '${first.implementationKey}' must be unique and canonically ordered"
    else if unknownAliases != []
    then fail "implementation '${first.implementationKey}' activated undeclared conditional requirements"
    else {
      implementation = first.implementationKey;
      inherit (first) providerInstance;
      requirements = aliases;
    };
  pendingRequirements = lib.filterAttrs (_: pending: pending.requirements != []) (
    builtins.mapAttrs (_: checkedPendingRequirementGroup) pendingRequirementGroups
  );
  noUnboundComposition =
    pendingRequests
    == {}
    && pendingRequirements == {};

  desiredResources = builtins.listToAttrs (builtins.concatLists (builtins.map (composition:
    builtins.map (resource: {
      name = "resource-${builtins.hashString "sha256" (builtins.toJSON resource.resource)}";
      value = {
        inherit (resource) kind lifetime value;
        controller = resource.controller.bindingName;
        realization = composition.result.realizations.${resource.resource.key};
      };
    })
    composition.resources)
  compositionGroups));

  outputFor = group: requestName: outputName: value: let
    request = group.context.requests.${requestName} or (fail "provider output references an unselected request '${requestName}'");
    requirement = abilities.requirementTemplates.${request.requirement};
    declarations = builtins.filter (interface: let
      identity = lib.abilities.interfaceIdentity (lib.abilities.interfaceDocumentFromDeclaration interface);
    in
      identity.name
      == requirement.interface
      && identity.abi == requirement.abi
      && identity.descriptor == requirement.descriptor)
    (builtins.attrValues abilities.interfaces);
    declaration =
      if builtins.length declarations == 1
      then builtins.head declarations
      else fail "request '${requestName}' does not resolve one exact output interface";
    descriptor = declaration.outputs.${outputName} or (fail "provider returned undeclared output '${outputName}' for '${requestName}'");
  in
    if !descriptor.schema.check value
    then fail "provider output '${requestName}.${outputName}' does not match its declared type"
    else {
      inherit value;
      inherit (descriptor) phase visibility lifetime;
    };
  expectedOutputEntries = builtins.concatLists (builtins.map (entry:
    builtins.map (outputName: {
      key = builtins.hashString "sha256" (builtins.toJSON {
        request = entry.binding.request;
        output = outputName;
      });
      requestName = entry.binding.request;
      inherit outputName;
    })
    (builtins.attrNames entry.interface.outputs))
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
in {
  config.aos.abilities.compositionPendingRequests = pendingRequests;
  config.aos.abilities.compositionPendingRequirements = pendingRequirements;

  config.aos.abilities.compositionOutputs =
    if !noUnboundComposition
    then fail "fixed-point provider child requests and conditional requirements need a selected binding projection"
    else if !outputSetValid
    then fail "selected providers must produce every declared output exactly once"
    else compositionOutputs;

  config.aos.abilities.desiredResources =
    if !noUnboundComposition
    then fail "fixed-point provider child requests and conditional requirements need a selected binding projection"
    else if !outputSetValid
    then fail "selected providers must produce every declared output exactly once"
    else desiredResources;
}
