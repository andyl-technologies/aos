##! Selects unambiguous providers for concrete requests between module rounds.
{
  lib,
  abilities,
}: let
  candidatesByName =
    builtins.mapAttrs (_: implementation: {
      inherit implementation;
    })
    abilities.implementations;
  pendingRequestDeclarations =
    builtins.mapAttrs (_: pending: pending.declaration)
    abilities.compositionPendingRequests;
  allRequests = abilities.requests // pendingRequestDeclarations;
  bindingNamesForRequest = requestName:
    builtins.filter
    (bindingName: abilities.bindings.${bindingName}.request == requestName)
    (builtins.attrNames abilities.bindings);

  requirementFor = requestName: request: let
    pending = abilities.compositionPendingRequests.${requestName} or null;
    requirement =
      abilities.requirementTemplates.${
        request.requirement
      }
      or (abilities.compositionRequirements.${
          request.requirement
        }.requirement or (
          if pending == null
          then null
          else abilities.implementations.${pending.implementation}.requirements.${pending.requirement}
          or null
        ));
  in
    if requirement == null
    then
      throw
      "ability request '${requestName}' references absent requirement '${request.requirement}'; pending origin: ${builtins.toJSON pending}"
    else requirement;
  guaranteeIdentityFor = context: reference:
    if builtins.isAttrs reference
    then reference
    else
      lib.abilities.guaranteeIdentity (
        abilities.guarantees.${reference}
        or (throw "${context} references absent guarantee declaration '${reference}'")
      );
  semanticInterfaceDeclaration = context: declaration:
    declaration
    // {
      guarantees =
        builtins.map
        (guarantee: guaranteeIdentityFor "${context} guarantee" guarantee)
        declaration.guarantees;
      methods = builtins.mapAttrs (methodName: method:
        method
        // {
          guarantees =
            builtins.map
            (guarantee: guaranteeIdentityFor "${context} method '${methodName}' guarantee" guarantee)
            method.guarantees;
        })
      declaration.methods;
    };
  interfaceDeclarationFor = implementation:
    if builtins.isString implementation.interface
    then abilities.interfaces.${implementation.interface}
      or (throw "ability implementation references absent interface '${implementation.interface}'")
    else let
      matches = builtins.filter (declaration:
        lib.abilities.interfaceIdentity (
          lib.abilities.interfaceDocumentFromDeclaration (
            semanticInterfaceDeclaration "ability implementation" declaration
          )
        )
        == implementation.interface)
      (builtins.attrValues abilities.interfaces);
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "ability implementation exact interface identity does not resolve to one declaration";
  interfaceIdentityFor = implementation:
    if builtins.isAttrs implementation.interface
    then implementation.interface
    else
      lib.abilities.interfaceIdentity (
        lib.abilities.interfaceDocumentFromDeclaration (
          semanticInterfaceDeclaration "ability implementation" (interfaceDeclarationFor implementation)
        )
      );
  implementationMatches = requirement: implementation: let
    interface = interfaceIdentityFor implementation;
    selectors =
      if requirement ? accepted_interfaces
      then requirement.accepted_interfaces
      else [
        ({
            name = requirement.interface;
            inherit (requirement) abi;
          }
          // lib.optionalAttrs (requirement.descriptor != null) {
            inherit (requirement) descriptor;
          })
      ];
    requiredGuarantees =
      builtins.map
      (guarantee: guaranteeIdentityFor "ability requirement" guarantee)
      requirement.guarantees;
    providedGuarantees =
      builtins.map
      (guarantee: guaranteeIdentityFor "ability implementation" guarantee)
      implementation.guarantees;
  in
    builtins.any
    (selector: lib.abilities.interfaceSelectorMatches selector interface)
    selectors
    && builtins.all
    (method: builtins.elem method implementation.methods)
    requirement.methods
    && builtins.all
    (guarantee: builtins.elem guarantee providedGuarantees)
    requiredGuarantees;
  candidateNamesFor = requirement:
    builtins.filter
    (name: implementationMatches requirement candidatesByName.${name}.implementation)
    (builtins.attrNames candidatesByName);
  packageForImplementation = implementationName: implementation:
    implementation.package
    or (builtins.head (lib.splitString ":" implementationName));

  generatedProviderInstance = implementationName: requestName: request: let
    implementation = abilities.implementations.${implementationName};
    declaration = interfaceDeclarationFor implementation;
    providerPackage = packageForImplementation implementationName implementation;
  in "selection:provider-${lib.abilities.identityKeyFor "aos.ability.selected-provider-instance/v1" (
    {
      inherit providerPackage;
      controllerGroup = declaration.aggregation.controllerGroup;
      environment = abilities.environment;
    }
    // lib.optionalAttrs declaration.aggregation.rejectSlotCollisions {
      scope = request.scope;
    }
    // lib.optionalAttrs declaration.aggregation.rejectSlotCollisions {
      consumer = request.consumer;
      slot = baseSlotFor requestName request;
    }
  )}";
  providerInstanceFor = implementationName: requestName: request: let
    matching =
      builtins.filter
      (name: abilities.instances.${name}.implementation == implementationName)
      (builtins.attrNames abilities.instances);
    pending = abilities.compositionPendingRequests.${requestName} or null;
    implementationPackage = builtins.head (lib.splitString ":" implementationName);
    parentPackage =
      if pending == null
      then null
      else builtins.head (lib.splitString ":" pending.implementation);
  in
    if builtins.length matching == 1
    then builtins.head matching
    else if
      pending
      != null
      && implementationPackage == parentPackage
      && builtins.hasAttr request.consumer abilities.instances
    then request.consumer
    else generatedProviderInstance implementationName requestName request;
  baseSlotFor = requestName: request:
    if builtins.hasAttr requestName abilities.compositionPendingRequests
    then abilities.compositionPendingRequests.${requestName}.slot
    else if request.scope != []
    then builtins.elemAt request.scope (builtins.length request.scope - 1)
    else if request.localKey or null != null
    then request.localKey
    else let
      components = lib.splitString ":" requestName;
    in
      builtins.elemAt components (builtins.length components - 1);
  unresolvedRequestNames =
    builtins.filter
    (name: bindingNamesForRequest name == [])
    (builtins.attrNames allRequests);
  duplicateBindings =
    builtins.filter
    (name: builtins.length (bindingNamesForRequest name) > 1)
    (builtins.attrNames allRequests);
  selectionFor = requestName: let
    request = allRequests.${requestName};
    requirement = requirementFor requestName request;
    candidates = candidateNamesFor requirement;
  in
    if builtins.length candidates == 1
    then let
      implementation = builtins.head candidates;
      candidate = candidatesByName.${implementation};
      providerInstance = providerInstanceFor implementation requestName request;
      declaration = interfaceDeclarationFor candidate.implementation;
      slot =
        if
          !declaration.aggregation.rejectSlotCollisions
          && declaration.aggregation.mergeContract != null
        then declaration.aggregation.key
        else baseSlotFor requestName request;
      binding = lib.abilities.staticBinding {
        request = requestName;
        inherit implementation providerInstance slot;
      };
    in {
      inherit implementation providerInstance requestName request requirement;
      package = packageForImplementation implementation candidate.implementation;
      bindingName = binding.name;
      bindingValue = binding.value;
    }
    else if candidates == [] && requirement.strength == "advisory"
    then null
    else if candidates == []
    then
      throw
      "ability request '${requestName}' in ${abilities.environment.stage} environment '${abilities.environment.key}' has no selected provider candidate for ${builtins.toJSON requirement}; pending origin: ${builtins.toJSON (abilities.compositionPendingRequests.${requestName} or null)}"
    else throw "ability request '${requestName}' in ${abilities.environment.stage} environment '${abilities.environment.key}' has ambiguous provider candidates: ${builtins.concatStringsSep ", " candidates}";
  selections = builtins.filter (selection: selection != null) (
    builtins.map selectionFor unresolvedRequestNames
  );
  selectedProviders =
    selections
    ++ builtins.map (binding: {
      inherit (binding) implementation providerInstance;
      package =
        packageForImplementation
        binding.implementation
        abilities.implementations.${binding.implementation};
    })
    (builtins.attrValues abilities.bindings);
  generatedInstances = builtins.listToAttrs (builtins.concatMap (provider:
    if builtins.hasAttr provider.providerInstance abilities.instances
    then []
    else [
      {
        name = provider.providerInstance;
        value = {
          inherit (provider) package;
          # One logical provider instance may aggregate several interface
          # implementations from the same package. Bindings select each exact
          # implementation; the instance owns only shared configuration and
          # identity, so synthesizing an arbitrary primary implementation here
          # would create a second, order-dependent source of truth.
          implementation = null;
          configuration = {};
        };
      }
    ])
  selectedProviders);
  generatedBindings = builtins.listToAttrs (builtins.map (selection: {
      name = selection.bindingName;
      value = selection.bindingValue;
    })
    selections);
  generatedRequests = builtins.listToAttrs (builtins.concatMap (selection:
    if builtins.hasAttr selection.requestName abilities.compositionPendingRequests
    then [
      {
        name = selection.requestName;
        value = selection.request;
      }
    ]
    else [])
  selections);
  generatedRequirements = builtins.listToAttrs (builtins.concatMap (selection:
    if builtins.hasAttr selection.requestName abilities.compositionPendingRequests
    then let
      pending = abilities.compositionPendingRequests.${selection.requestName};
    in [
      {
        name = selection.request.requirement;
        value = {
          inherit (pending) implementation;
          alias = pending.requirement;
          requirement = selection.requirement;
        };
      }
    ]
    else [])
  selections);
in
  if abilities.environment == null
  then throw "ability provider selection requires an explicit target environment"
  else if duplicateBindings != []
  then throw "ability requests have several selected bindings: ${builtins.concatStringsSep ", " duplicateBindings}"
  else {
    instances = generatedInstances;
    bindings = generatedBindings;
    requests = generatedRequests;
    requirements = generatedRequirements;
  }
