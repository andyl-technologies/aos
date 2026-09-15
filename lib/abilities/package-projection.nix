##! Canonical symbolic package projection from evaluated ability options.
{
  lib,
  abilities,
}: {
  packageName,
  version,
  evaluated,
  packageModuleLocator ? null,
}: let
  packagePrefix = "${packageName}:";
  localName = name:
    if lib.hasPrefix packagePrefix name
    then builtins.substring (builtins.stringLength packagePrefix) (-1) name
    else name;
  selector = value: builtins.removeAttrs value ["_type"];
  defaultArtifact = abilities.packageOutput {};
  implementationNames = builtins.attrNames evaluated.implementations;
  structuredEffects = builtins.any (name: let
    implementation = evaluated.implementations.${name};
  in
    implementation.compose != null
    || implementation.transition != null
    || implementation.provide != null
    || implementation.handlerDescriptor != null)
  implementationNames;

  interfaceDocuments = builtins.mapAttrs (
    _:
      abilities.interfaceDocumentFromDeclaration
  ) evaluated.interfaces;
  interfaceFor = implementation: interfaceDocuments.${implementation.interface};
  interfaceIdentityFor = implementation:
    abilities.interfaceIdentity (interfaceFor implementation);
  requirementsFor = implementation:
    map (name: implementation.requirements.${name})
    (builtins.attrNames implementation.requirements);
  packageRequirements = abilities.normalizeRequirements (builtins.listToAttrs (map (name: {
      name = localName name;
      value = evaluated.requirementTemplates.${name};
    })
    (builtins.attrNames evaluated.requirementTemplates)));
  guarantees = builtins.listToAttrs (map (name: {
      name = localName name;
      value = evaluated.guarantees.${name};
    })
    (builtins.attrNames evaluated.guarantees));
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
  ownedResourceKinds = implementation: let
    declaration = interfaceFor implementation;
  in
    builtins.attrNames (builtins.listToAttrs (map
      (method: {
        name = declaration.methods.${method}.targetResource;
        value = true;
      })
      (builtins.filter
        (method:
          declaration.methods.${method}.semantics.requiredTargetAccess
          == "exclusive-write")
        implementation.methods)));
  providerFor = name: implementation: let
    artifact = implementationArtifact implementation;
    interface = interfaceIdentityFor implementation;
    terminal = implementation.handlerDescriptor != null;
  in
    {
      name = localName name;
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
    leftInterface = builtins.toJSON left.interface;
    rightInterface = builtins.toJSON right.interface;
  in
    if leftInterface == rightInterface
    then left.name < right.name
    else leftInterface < rightInterface;
  providers = builtins.sort providerLessThan (map
    (name: providerFor name evaluated.implementations.${name})
    implementationNames);
  handlerPairs = lib.concatMap (name: let
    implementation = evaluated.implementations.${name};
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
  artifactSelectors = lib.unique (lib.concatMap (name: let
      implementation = evaluated.implementations.${name};
    in
      [(implementationArtifact implementation)]
      ++ map selector implementation.artifacts
      ++ lib.optional
      (implementation.providerModule != null)
      (selector implementation.providerModule.artifact)
      ++ lib.optional
      (implementation.handlerDescriptor != null)
      (selector implementation.handlerDescriptor.artifact))
    implementationNames);
  interfaceAliases = map (name: let
    document = interfaceDocuments.${name};
    identity = abilities.interfaceIdentity document;
  in {
    name = localName name;
    descriptor = identity.descriptor;
    declaration = evaluated.interfaces.${name};
    value = document;
    document = builtins.toFile
      "ability-interface-${packageName}-${localName name}.json"
      (builtins.toJSON document);
  }) (builtins.attrNames interfaceDocuments);
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
    }) interfaceAliases);
    inherit guarantees;
    package_module = packageModuleLocator;
    exports = map (name: let
      implementation = evaluated.implementations.${name};
    in {
      name = localName name;
      interface = interfaceIdentityFor implementation;
      implementation = localName name;
    }) implementationNames;
    interface_documents = map (entry: {
      inherit (entry) descriptor;
      document = entry.value;
    }) interfaceEntries;
    requirements = packageRequirements;
    implementation = {
      inherit providers;
      handlers = builtins.listToAttrs handlerPairs;
    };
  };
in {
  value = projectionValue;
  document = builtins.toFile
    "ability-package-projection-${packageName}.json"
    (builtins.toJSON projectionValue);
  interfaces = interfaceEntries;
}
