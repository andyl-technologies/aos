##! Canonical symbolic package projection from evaluated ability options.
{
  lib,
  abilities,
}: {
  packageName,
  version,
  evaluated,
  packageModuleLocator ? null,
  optionDeclarations ? [],
}: let
  packagePrefix = "${packageName}:";
  localName = name:
    if lib.hasPrefix packagePrefix name
    then builtins.substring (builtins.stringLength packagePrefix) (-1) name
    else name;
  selector = value: builtins.removeAttrs value ["_type"];
  defaultArtifact = abilities.packageOutput {};
  packageOwnedNames = values:
    builtins.filter (name: lib.hasPrefix packagePrefix name) (builtins.attrNames values);
  implementationNames = packageOwnedNames evaluated.implementations;
  structuredEffects = builtins.any (name: let
    implementation = evaluated.implementations.${name};
  in
    implementation.compose
    != null
    || implementation.transition != null
    || implementation.provide != null
    || implementation.handlerDescriptor != null)
  implementationNames;

  guaranteeFor = reference:
    if !builtins.isString reference
    then throw "Ability guarantee references must be exact declaration aliases."
    else if builtins.hasAttr reference evaluated.guarantees
    then abilities.guaranteeIdentity evaluated.guarantees.${reference}
    else throw "Ability guarantee reference '${reference}' has no exact package declaration.";
  semanticRequirement = requirement:
    requirement // {guarantees = map guaranteeFor requirement.guarantees;};
  semanticInterface = interface:
    interface
    // {
      guarantees = map guaranteeFor interface.guarantees;
      methods = builtins.mapAttrs (_: method:
        method // {guarantees = map guaranteeFor method.guarantees;})
      interface.methods;
    };
  semanticImplementation = implementation:
    implementation
    // {
      guarantees = map guaranteeFor implementation.guarantees;
      requirements = builtins.mapAttrs (_: semanticRequirement) implementation.requirements;
    };
  semanticImplementations = builtins.mapAttrs (_: semanticImplementation) evaluated.implementations;

  interfaceDocuments = builtins.mapAttrs (name: declaration:
    abilities.interfaceDocumentFromDeclaration (
      if lib.hasPrefix packagePrefix name
      then semanticInterface declaration
      else declaration
    ))
  evaluated.interfaces;
  ownedInterfaceDocuments =
    lib.filterAttrs (
      name: _: lib.hasPrefix packagePrefix name
    )
    interfaceDocuments;
  interfaceFor = implementation:
    if builtins.isString implementation.interface
    then interfaceDocuments.${implementation.interface}
    else let
      matches = builtins.filter (document:
        abilities.interfaceIdentity document == implementation.interface)
      (builtins.attrValues interfaceDocuments);
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "Implementation interface identity must resolve to one canonical shared declaration.";
  interfaceIdentityFor = implementation:
    abilities.interfaceIdentity (interfaceFor implementation);
  requirementsFor = implementation:
    map (name: implementation.requirements.${name})
    (builtins.attrNames implementation.requirements);
  packageRequirements = abilities.normalizeRequirements (builtins.listToAttrs (map (name: {
      name = localName name;
      value = semanticRequirement evaluated.requirementTemplates.${name};
    })
    (packageOwnedNames evaluated.requirementTemplates)));
  guarantees = builtins.listToAttrs (map (name: {
      name = localName name;
      value = evaluated.guarantees.${name};
    })
    (packageOwnedNames evaluated.guarantees));
  implementationArtifact = implementation:
    selector (
      if implementation.artifact == null
      then defaultArtifact
      else implementation.artifact
    );
  moduleLocator = implementation: {
    artifact = selector implementation.providerModule.artifact;
    inherit (implementation.providerModule) path;
  };
  projectedHandler = context: handler:
    (builtins.removeAttrs handler ["arguments" "result"])
    // {
      arguments = abilities.types.schemaOf "${context} arguments" handler.arguments;
      result = abilities.types.schemaOf "${context} result" handler.result;
    };
  ownedResourceKinds = implementation: let
    declaration = interfaceFor implementation;
  in
    builtins.attrNames (builtins.listToAttrs (map
      (method: {
        name = declaration.interface.methods.${method}.target_resource;
        value = true;
      })
      (builtins.filter
        (method:
          declaration.interface.methods.${method}.semantics.required_target_access
          == "exclusive-write")
        implementation.methods)));
  providerFor = name: implementation: let
    artifact = implementationArtifact implementation;
    interface = interfaceIdentityFor implementation;
    terminal = implementation.handlerDescriptor != null;
  in
    {
      name = localName name;
      inherit (implementation) description;
      inherit (implementation) guarantees;
      inherit artifact interface;
      requirements = requirementsFor implementation;
      owns_resource_kinds = ownedResourceKinds implementation;
      desired_schema =
        if implementation.desiredType == null
        then null
        else abilities.types.schemaOf "implementation desired realization" implementation.desiredType;
    }
    // lib.optionalAttrs (implementation.providerModule != null) {
      provider_module = moduleLocator implementation;
    }
    // lib.optionalAttrs terminal {
      handler = localName name;
    }
    // lib.optionalAttrs (implementation.state_format != null) {
      state_format = {
        descriptor = implementation.state_format;
        inherit artifact;
      };
    };
  providerLessThan = left: right: let
    leftInterface = left.interface;
    rightInterface = right.interface;
  in
    if leftInterface.name != rightInterface.name
    then leftInterface.name < rightInterface.name
    else if leftInterface.abi != rightInterface.abi
    then leftInterface.abi < rightInterface.abi
    else if leftInterface.descriptor != rightInterface.descriptor
    then leftInterface.descriptor < rightInterface.descriptor
    else left.name < right.name;
  providers = builtins.sort providerLessThan (map
    (name: providerFor name semanticImplementations.${name})
    implementationNames);
  handlerPairs = lib.concatMap (name: let
    implementation = semanticImplementations.${name};
    handler = implementation.handlerDescriptor;
  in
    lib.optional (handler != null) {
      name = localName name;
      value = {
        artifact = selector handler.artifact;
        entry_point = handler.entryPoint;
        arguments = abilities.types.schemaOf "handler arguments" handler.arguments;
        result = abilities.types.schemaOf "handler result" handler.result;
      };
    })
  implementationNames;
  artifactSelectors =
    builtins.sort
    (left: right: builtins.toJSON left < builtins.toJSON right)
    (lib.unique (
      lib.optional
      (packageModuleLocator != null)
      (selector packageModuleLocator.artifact)
      ++ lib.concatMap (name: let
        implementation = semanticImplementations.${name};
      in
        [(implementationArtifact implementation)]
        ++ map selector implementation.artifacts
        ++ lib.optional
        (implementation.providerModule != null)
        (selector implementation.providerModule.artifact)
        ++ lib.optional
        (implementation.handlerDescriptor != null)
        (selector implementation.handlerDescriptor.artifact)
        ++ lib.optional
        (implementation.qualification != null)
        (selector implementation.qualification.observer.artifact))
      implementationNames
    ));
  qualification = builtins.listToAttrs (lib.concatMap (name: let
    implementation = semanticImplementations.${name};
  in
    lib.optional (implementation.qualification != null) {
      name = localName name;
      value = {
        conformance_families = builtins.sort builtins.lessThan implementation.qualification.conformanceFamilies;
        observer =
          projectedHandler
          "qualification observer"
          implementation.qualification.observer;
      };
    })
  implementationNames);
  interfaceAliases = map (name: let
    document = interfaceDocuments.${name};
    identity = abilities.interfaceIdentity document;
  in {
    name = localName name;
    descriptor = identity.descriptor;
    value = document;
  }) (builtins.attrNames ownedInterfaceDocuments);
  interfaceEntries = builtins.attrValues (builtins.listToAttrs (map (entry: {
      name = entry.descriptor;
      value = entry;
    })
    interfaceAliases));
  projectionValue = {
    schema = "aos.ability.package-projection/v1";
    required_features = lib.sort builtins.lessThan (lib.unique (
      ["abilities-v1"]
      ++ lib.concatMap
      (name: evaluated.implementations.${name}.requiredFeatures)
      implementationNames
      ++ lib.optional
      (builtins.any
        (name: evaluated.implementations.${name}.state_format != null)
        implementationNames)
      "provider-state-format-v1"
    ));
    activation_mode =
      if structuredEffects
      then "structured-effects"
      else "contracts-only";
    package = {
      name = packageName;
      inherit version;
    };
    artifacts = artifactSelectors;
    interfaces = builtins.listToAttrs (map (entry: {
        name = localName entry.name;
        value = abilities.interfaceIdentity entry.value;
      })
      interfaceAliases);
    inherit guarantees;
    package_module =
      if packageModuleLocator == null
      then null
      else {
        artifact = selector packageModuleLocator.artifact;
        inherit (packageModuleLocator) path;
      };
    option_declarations = optionDeclarations;
    exports =
      map (name: let
        implementation = semanticImplementations.${name};
      in {
        name = localName name;
        interface = interfaceIdentityFor implementation;
        implementation = localName name;
      })
      implementationNames;
    interface_documents =
      map (entry: {
        inherit (entry) descriptor;
        document = entry.value;
      })
      interfaceEntries;
    requirements = packageRequirements;
    implementation = {
      inherit providers;
      handlers = builtins.listToAttrs handlerPairs;
    };
    inherit qualification;
  };
in {
  value = projectionValue;
  selectors = artifactSelectors;
}
