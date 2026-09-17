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
  packageProbe ? null,
}: let
  ownedNames = values:
    builtins.attrNames (lib.filterAttrs (_: value:
      (value.package or null) == packageName
      && value.localKey != null)
    values);
  declarationAliasFor = collection: name: let
    declaration = evaluated.${collection}.${name};
  in
    if declaration.package == packageName && declaration.localKey != null
    then declaration.localKey
    else throw "Package '${packageName}' cannot project foreign ${collection} declaration '${name}'.";
  selector = value: let
    selected = builtins.removeAttrs value ["_type"];
  in
    selected
    // {
      package =
        if selected.package == "self"
        then packageName
        else selected.package;
    };
  defaultArtifact = abilities.packageOutput {};
  implementationNames = ownedNames evaluated.implementations;
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
    then abilities.guaranteeIdentity (builtins.removeAttrs evaluated.guarantees.${reference} ["package" "localKey"])
    else throw "Ability guarantee reference '${reference}' has no exact package declaration.";
  semanticRequirement = requirement:
    builtins.removeAttrs requirement ["package" "localKey"]
    // {guarantees = map guaranteeFor requirement.guarantees;};
  semanticInterface = interface:
    builtins.removeAttrs interface ["package" "localKey"]
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
  projectedPackageProbe =
    if packageProbe == null
    then null
    else
      lib.qualification.projectPackageProbe {
        owner = packageName;
        probe = packageProbe;
      };

  interfaceDocuments = builtins.mapAttrs (_: declaration:
    abilities.interfaceDocumentFromDeclaration (semanticInterface declaration))
  evaluated.interfaces;
  ownedInterfaceDocuments =
    lib.filterAttrs (
      name: _: evaluated.interfaces.${name}.package == packageName
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
      name = declarationAliasFor "requirementTemplates" name;
      value = semanticRequirement evaluated.requirementTemplates.${name};
    })
    (ownedNames evaluated.requirementTemplates)));
  guarantees = builtins.listToAttrs (map (name: {
      name = declarationAliasFor "guarantees" name;
      value = builtins.removeAttrs evaluated.guarantees.${name} ["package" "localKey"];
    })
    (ownedNames evaluated.guarantees));
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
  projectedHandler = context: handler: {
    artifact = selector handler.artifact;
    entry_point = handler.entryPoint;
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
      name = implementation.localKey;
      inherit (implementation) description;
      inherit (implementation) guarantees;
      inherit artifact interface;
      requirements = requirementsFor implementation;
      owns_resource_kinds = ownedResourceKinds implementation;
      desired_schema =
        if implementation.desiredType == null
        then null
        else abilities.types.schemaOf "implementation desired realization" implementation.desiredType;
      composition_schema =
        if implementation.compositionType == null
        then null
        else abilities.types.schemaOf "implementation composition resource" implementation.compositionType;
    }
    // lib.optionalAttrs (implementation.providerModule != null) {
      provider_module = moduleLocator implementation;
    }
    // lib.optionalAttrs terminal {
      handler = implementation.localKey;
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
      name = implementation.localKey;
      value = {
        artifact = selector handler.artifact;
        entry_point = handler.entryPoint;
        arguments = abilities.types.schemaOf "handler arguments" handler.arguments;
        result = abilities.types.schemaOf "handler result" handler.result;
      };
    })
  implementationNames;
  artifactSelectors =
    abilities.canonicalizePackageOutputSelectors (
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
      ++ lib.optionals (projectedPackageProbe != null) projectedPackageProbe.selectors
    );
  implementationQualification = builtins.listToAttrs (lib.concatMap (name: let
      implementation = semanticImplementations.${name};
      qualification = implementation.qualification;
    in
      lib.optional (qualification != null) {
        name = implementation.localKey;
        value = {
          inherit (qualification) adapter scope;
          observation_kind = qualification.observationKind;
          conformance_families = builtins.sort builtins.lessThan qualification.conformanceFamilies;
          observer = projectedHandler "qualification observer" qualification.observer;
        };
      })
    implementationNames);
  interfaceAliases = map (name: let
    document = interfaceDocuments.${name};
    identity = abilities.interfaceIdentity document;
  in {
    name = declarationAliasFor "interfaces" name;
    descriptor = identity.descriptor;
    value = document;
  }) (builtins.attrNames ownedInterfaceDocuments);
  implementedInterfaceAliases = map (name: let
    document = interfaceFor semanticImplementations.${name};
    identity = abilities.interfaceIdentity document;
  in {
    name = semanticImplementations.${name}.localKey;
    descriptor = identity.descriptor;
    value = document;
  }) implementationNames;
  allInterfaceAliases = interfaceAliases ++ implementedInterfaceAliases;
  projectedInterfaces = builtins.listToAttrs (map (entry: {
      inherit (entry) name;
      value = abilities.interfaceIdentity entry.value;
    })
    allInterfaceAliases);
  interfaceAliasesAgree = builtins.all (
    entry: projectedInterfaces.${entry.name} == abilities.interfaceIdentity entry.value
  ) allInterfaceAliases;
  implementedInterfaceEntries = map (name: let
    document = interfaceFor semanticImplementations.${name};
    identity = abilities.interfaceIdentity document;
  in {
    name = identity.descriptor;
    value = {
      descriptor = identity.descriptor;
      value = document;
    };
  }) implementationNames;
  interfaceEntries = builtins.attrValues (builtins.listToAttrs (
    (map (entry: {
        name = entry.descriptor;
        value = entry;
      })
      interfaceAliases)
    ++ implementedInterfaceEntries
  ));
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
      ++ lib.optional structuredEffects "ability-effects-v1"
    ));
    package = {
      name = packageName;
      inherit version;
    };
    artifacts = artifactSelectors;
    interfaces =
      if interfaceAliasesAgree
      then projectedInterfaces
      else throw "Package interface and implementation aliases resolve to conflicting declarations.";
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
        name = implementation.localKey;
        interface = interfaceIdentityFor implementation;
        implementation = implementation.localKey;
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
    qualification =
      {implementations = implementationQualification;}
      // lib.optionalAttrs (projectedPackageProbe != null) {
        package_probe = projectedPackageProbe.value;
      };
  };
  nativeAbilities = abilities.packageAbilitiesFromProjection projectionValue;
in {
  value = projectionValue;
  selectors = artifactSelectors;
  abilities = nativeAbilities;
}
