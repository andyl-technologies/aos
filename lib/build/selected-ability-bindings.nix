##! Resolves build-time ability bindings from selected package modules.
##!
##! Image evaluation has no external package resolver. This driver applies the
##! same exact interface, method, guarantee, and provider-instance constraints
##! to the packages already selected by the stage-one module evaluation, then
##! repeats evaluation until provider-authored child requests are closed.
{lib}: {
  evaluate,
  maxRounds ? 16,
}: let
  fail = message: throw "selected ability binding projection: ${message}";
  packageOf = declaration: builtins.head (lib.splitString ":" declaration);

  guaranteeIdentityFor = abilities: reference:
    if builtins.isString reference
    then
      lib.abilities.guaranteeIdentity (
        abilities.guarantees.${reference}
        or (fail "guarantee '${reference}' has no selected declaration")
      )
    else reference;
  interfaceIdentityFor = abilities: implementationName: implementation:
    if builtins.isAttrs implementation.interface
    then implementation.interface
    else let
      declaration =
        abilities.interfaces.${implementation.interface}
        or (fail "implementation '${implementationName}' has no selected interface");
      semantic =
        declaration
        // {
          guarantees = builtins.map (guaranteeIdentityFor abilities) declaration.guarantees;
          methods = builtins.mapAttrs (_: method:
            method
            // {
              guarantees = builtins.map (guaranteeIdentityFor abilities) method.guarantees;
            })
          declaration.methods;
        };
    in
      lib.abilities.interfaceIdentity (
        lib.abilities.interfaceDocumentFromDeclaration semantic
      );
  semanticImplementationGuarantees = abilities: implementation:
    builtins.map (guaranteeIdentityFor abilities) implementation.guarantees;

  authoredRequirement = abilities: requestName: request: let
    requirement =
      abilities.requirementTemplates.${request.requirement}
      or (fail "request '${requestName}' has no selected requirement");
  in {
    acceptedInterfaces = [
      ({
          name = requirement.interface;
          inherit (requirement) abi;
        }
        // lib.optionalAttrs (requirement.descriptor != null) {
          inherit (requirement) descriptor;
        })
    ];
    inherit (requirement) methods;
    guarantees = builtins.map (guaranteeIdentityFor abilities) requirement.guarantees;
  };
  providerRequirement = abilities: requestName: pending: let
    generated =
      abilities.compositionRequirements.${pending.declaration.requirement}
      or (fail "provider request '${requestName}' has no generated requirement");
  in {
    acceptedInterfaces = generated.requirement.accepted_interfaces;
    inherit (generated.requirement) methods guarantees;
  };

  implementationMatches = abilities: requirement: implementationName: let
    implementation = abilities.implementations.${implementationName};
    identity = interfaceIdentityFor abilities implementationName implementation;
  in
    builtins.any
    (selector: lib.abilities.interfaceSelectorMatches selector identity)
    requirement.acceptedInterfaces
    && builtins.all (method: builtins.elem method implementation.methods) requirement.methods
    && builtins.all
    (guarantee: builtins.elem guarantee (semanticImplementationGuarantees abilities implementation))
    requirement.guarantees;

  implementationFor = abilities: requestName: requirement: let
    candidates =
      builtins.filter
      (implementationMatches abilities requirement)
      (builtins.attrNames abilities.implementations);
  in
    if builtins.length candidates == 1
    then builtins.head candidates
    else
      fail
      "request '${requestName}' resolves to ${builtins.toString (builtins.length candidates)} selected implementations for ${builtins.toJSON requirement.acceptedInterfaces}";

  providerInstanceFor = abilities: implementationName: let
    implementation = abilities.implementations.${implementationName};
    providerPackage = packageOf implementationName;
    packageInstances =
      lib.filterAttrs
      (name: _: packageOf name == providerPackage)
      abilities.instances;
    exact =
      builtins.filter
      (name: packageInstances.${name}.implementation == implementationName)
      (builtins.attrNames packageInstances);
    generic =
      builtins.filter
      (name: packageInstances.${name}.implementation == null)
      (builtins.attrNames packageInstances);
    moduleMatched = builtins.filter (name:
      implementation.providerModule
      != null
      && lib.hasInfix
      (lib.removePrefix "${providerPackage}:" name)
      implementation.providerModule.path)
    generic;
    synthesized = "build:provider-${builtins.hashString "sha256" (builtins.toJSON {
      package = providerPackage;
      module =
        if implementation.providerModule == null
        then implementationName
        else implementation.providerModule.path;
    })}";
  in
    if builtins.length exact == 1
    then builtins.head exact
    else if exact == [] && builtins.length generic == 1
    then builtins.head generic
    else if exact == [] && builtins.length moduleMatched == 1
    then builtins.head moduleMatched
    else if exact == [] && generic == []
    then synthesized
    else
      fail
      "implementation '${implementationName}' resolves to ${builtins.toString (builtins.length exact)} exact and ${builtins.toString (builtins.length generic)} generic provider instances";

  bindingFor = {
    abilities,
    requestName,
    requirement,
    slot,
    implementation ? null,
    providerInstance ? null,
  }: let
    selectedImplementation =
      if implementation == null
      then implementationFor abilities requestName requirement
      else implementation;
  in {
    name = "build:binding-${builtins.hashString "sha256" requestName}";
    value = {
      request = requestName;
      implementation = selectedImplementation;
      inherit slot;
      providerInstance =
        if providerInstance == null
        then providerInstanceFor abilities selectedImplementation
        else providerInstance;
    };
  };

  resolve = round: bindings: let
    evaluated = evaluate bindings;
    abilities = evaluated.config.aos.abilities;
    alreadyBound = requestName:
      builtins.any
      (binding: binding.request == requestName)
      (builtins.attrValues abilities.bindings);
    authored = lib.filterAttrs (name: _: !alreadyBound name) abilities.requests;
    provider = lib.filterAttrs (name: _: !alreadyBound name) abilities.compositionPendingRequests;
    authoredSelections =
      builtins.mapAttrs (requestName: request: let
        requirement = authoredRequirement abilities requestName request;
      in {
        inherit requirement;
        implementation = implementationFor abilities requestName requirement;
        baseSlot =
          if request.scope == []
          then fail "request '${requestName}' has no package-authored contribution slot"
          else builtins.head request.scope;
      })
      authored;
    authoredBindings = builtins.map (requestName: let
      selection = authoredSelections.${requestName};
      sameImplementationSlotRequests = lib.filterAttrs (_: other:
        other.baseSlot
        == selection.baseSlot
        && other.implementation == selection.implementation)
      authoredSelections;
      # Feature requests for one logical service retain their shared slot
      # across implementations. Repeated requests to the same implementation
      # need distinct resource identities within a provider instance.
      slot =
        if builtins.length (builtins.attrNames sameImplementationSlotRequests) == 1
        then selection.baseSlot
        else "root-${builtins.hashString "sha256" requestName}";
    in
      bindingFor {
        inherit abilities requestName slot;
        inherit (selection) implementation requirement;
      })
    (builtins.attrNames authored);
    providerBindings = builtins.map (requestName: let
      pending = provider.${requestName};
    in
      bindingFor {
        inherit abilities requestName;
        requirement = providerRequirement abilities requestName pending;
        inherit (pending) slot;
      })
    (builtins.attrNames provider);
    additions = builtins.listToAttrs (authoredBindings ++ providerBindings);
  in
    if authored == {} && provider == {}
    then
      if abilities.requests != {} && abilities.bindings == {}
      then fail "nonempty selected requests produced no bindings"
      else evaluated
    else if round >= maxRounds
    then fail "provider composition did not close within ${builtins.toString maxRounds} rounds"
    else resolve (round + 1) (bindings // additions);
in
  resolve 0 {}
