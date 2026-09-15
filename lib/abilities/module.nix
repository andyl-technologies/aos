##! Canonical ability options for the AOS module fixed point.
##!
##! This module owns the shared container types only. Packages and providers
##! contribute their declarations through ordinary modules, and semantic
##! validation resolves references after the complete fixed point evaluates.
{
  config ? null,
  mkOption,
  moduleTypes,
  abilityTypes,
  schemas,
  evalModules,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  strictSubmodule = options: let
    submoduleType = moduleTypes.submodule {
      _file = "<lib.abilities.module>";
      _module.strict = true;
      inherit options;
    };
  in
    submoduleType
    // {
      merge = location: definitions:
        builtins.removeAttrs (submoduleType.merge location definitions) ["_module"];
    };

  checkedSubmodule = name: baseType: check:
    baseType
    // {
      merge = location: definitions: let
        value = baseType.merge location definitions;
      in
        if check value
        then value
        else throw "The option '${builtins.concatStringsSep "." location}' is not a valid ${name}.";
    };

  checkedType = name: description: check:
    moduleTypes.mkOptionType {
      inherit name;
      inherit description check;
      merge = location: definitions: let
        value = moduleTypes.mergeEqualOption location definitions;
      in
        if check value
        then value
        else throw "The option '${builtins.concatStringsSep "." location}' must be a ${name}.";
    };

  portableType =
    checkedType "portable ability option type" "option type with a portable schema projection" (value:
      moduleTypes.optionType.check value && value ? _abilitySchema);
  portableSchemaType =
    checkedType "portable ability schema" "validated portable ability schema" (value:
      (builtins.tryEval (builtins.deepSeq (schemas.validateSchema "module ability schema" value) true)).success);
  isCanonicalValue = depth: value:
    depth
    <= 64
    && (
      value
      == null
      || builtins.isBool value
      || (builtins.isInt value && value >= -9007199254740991 && value <= 9007199254740991)
      || (builtins.isString value && builtins.stringLength value <= 1048576)
      || (builtins.isList value && builtins.all (isCanonicalValue (depth + 1)) value)
      || (
        builtins.isAttrs value
        && builtins.all (
          name:
            builtins.stringLength name
            <= 1048576
            && isCanonicalValue (depth + 1) value.${name}
        ) (builtins.attrNames value)
      )
    );
  canonicalValueType =
    checkedType "canonical ability value" "bounded JSON-compatible ability value"
    (isCanonicalValue 0);
  descriptionType = checkedType "non-empty description" "bounded human-readable declaration prose" (value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 4096);

  packageForDefinition = definition:
    if builtins.match "package:.+" (definition.provenance or "") == null
    then null
    else builtins.substring 8 (builtins.stringLength definition.provenance - 8) definition.provenance;
  qualify = package: name:
    if package == null
    then name
    else "${package}:${name}";
  qualifyDeferredResults = package: value:
    if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then value // {request = qualify package value.request;}
    else if builtins.isAttrs value
    then builtins.mapAttrs (_: qualifyDeferredResults package) value
    else if builtins.isList value
    then builtins.map (qualifyDeferredResults package) value
    else value;
  qualifyAbilityValue = collection: package: value:
    if package == null
    then value
    else if collection == "implementations"
    then
      value
      // {package = package;}
      // (
        if value ? interface
        then {interface = qualify package value.interface;}
        else {}
      )
    else if collection == "instances"
    then
      (qualifyDeferredResults package value)
      // (
        if !(value ? implementation)
        then {}
        else {
          implementation =
            if value.implementation == null
            then null
            else qualify package value.implementation;
        }
      )
    else if collection == "requests"
    then
      (qualifyDeferredResults package value)
      // {package = package;}
      // (
        if value ? requirement
        then {requirement = qualify package value.requirement;}
        else {}
      )
      // (
        if value ? consumer
        then {consumer = qualify package value.consumer;}
        else {}
      )
    else value;
  abilityMapType = collection: elementType: let
    base = moduleTypes.attrsOf elementType;
  in
    base
    // {
      merge = location: definitions:
        base.merge location (builtins.map (definition: let
          package = packageForDefinition definition;
        in
          definition
          // {
            value = builtins.listToAttrs (builtins.map (name: {
                name = qualify package name;
                value = qualifyAbilityValue collection package definition.value.${name};
              })
              (builtins.attrNames definition.value));
          })
        definitions);
    };
  functionType = {
    name = "ability constructor";
    description = "pure ability constructor function";
    check = builtins.isFunction;
    merge = location: definitions: let
      value = (builtins.elemAt definitions (builtins.length definitions - 1)).value;
    in
      if builtins.isFunction value
      then value
      else throw "The option '${builtins.concatStringsSep "." location}' must be an ability constructor function.";
  };

  isLocalKey = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9._-]+" value != null;
  localKeyType = abilityTypes.localKey;
  packageNameType = abilityTypes.packageName;
  declarationKeyType = abilityTypes.declarationKey;
  packageOutputType = abilityTypes.packageOutputSelector;
  relativePathType = abilityTypes.relativePath;
  qualifiedNameType = abilityTypes.qualifiedName;
  digestType = abilityTypes.digest;
  positiveU32Type =
    moduleTypes.addCheck moduleTypes.int (value:
      value > 0 && value <= 4294967295);
  stageType = abilityTypes.stage;
  lifetimeType = abilityTypes.lifetime;

  interfaceKeyType = abilityTypes.interfaceKey;
  uniqueValues = values:
    builtins.length values
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = builtins.toJSON value;
        value = true;
      })
      values)));

  projectedOutputType = strictSubmodule {
    schema = mkOption {
      type = portableSchemaType;
      description = "Portable output value schema projected from its authored option type.";
    };
    phase = mkOption {
      type = moduleTypes.enum ["evaluation" "artifact" "planning" "admission" "runtime" "observation"];
      description = "First phase in which the output is available.";
    };
    visibility = mkOption {
      type = moduleTypes.enum ["public" "protected" "private"];
      description = "Output visibility.";
    };
    lifetime = mkOption {
      type = lifetimeType;
      description = "Output retention lifetime.";
    };
  };

  projectedOutcomeType = strictSubmodule {
    completion_evidence = mkOption {
      type = portableSchemaType;
      description = "Evidence schema for a completed external operation.";
    };
    observation_evidence = mkOption {
      type = portableSchemaType;
      description = "Evidence schema used to reconcile an uncertain operation.";
    };
    supports_rejected_before_effect = mkOption {
      type = moduleTypes.bool;
      description = "Whether the method distinguishes rejection before an external effect.";
    };
    indeterminate = mkOption {
      type = moduleTypes.enum ["reconcile" "intervention-required"];
      description = "Required handling for an indeterminate external effect.";
    };
  };

  authoredMethodSemanticsBaseType = strictSubmodule {
    requiredTargetAccess = mkOption {
      type = moduleTypes.enum ["read" "shared-write" "exclusive-write"];
    };
    stopsProvider = mkOption {type = moduleTypes.bool;};
  };
  authoredMethodSemanticsType =
    checkedSubmodule "authored method semantics" authoredMethodSemanticsBaseType
    (semantics: !semantics.stopsProvider || semantics.requiredTargetAccess == "exclusive-write");

  projectedMethodSemanticsBaseType = strictSubmodule {
    required_target_access = mkOption {
      type = moduleTypes.enum ["read" "shared-write" "exclusive-write"];
    };
    stops_provider = mkOption {type = moduleTypes.bool;};
  };
  projectedMethodSemanticsType =
    checkedSubmodule "projected method semantics" projectedMethodSemanticsBaseType
    (semantics: !semantics.stops_provider || semantics.required_target_access == "exclusive-write");

  projectedMethodType = strictSubmodule {
    semantics = mkOption {type = projectedMethodSemanticsType;};
    parameters = mkOption {
      type = portableSchemaType;
      description = "Portable parameter schema projected from the authored option type.";
    };
    target_resource = mkOption {
      type = qualifiedNameType;
      description = "Resource interface controlled by the method.";
    };
    outputs = mkOption {
      type = moduleTypes.attrsOf projectedOutputType;
      default = {};
      description = "Named method outputs.";
    };
    permitted_operations = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
      description = "Operations a caller may authorize through this method.";
    };
    guarantees = mkOption {
      type = moduleTypes.listOf guaranteeType;
      default = [];
      description = "Guarantees promised by the method.";
    };
    outcome = mkOption {
      type = projectedOutcomeType;
      description = "Completion and reconciliation semantics.";
    };
  };

  projectedLifecycleType = strictSubmodule {
    stable_resource_identity = mkOption {type = moduleTypes.bool;};
    releases_ephemeral_on_disable = mkOption {type = moduleTypes.bool;};
    retains_persistent_by_default = mkOption {type = moduleTypes.bool;};
    persistent_delete_method = mkOption {
      type = moduleTypes.nullOr packageNameType;
    };
  };

  projectedAggregationType = strictSubmodule {
    scope = mkOption {type = moduleTypes.enum ["provider-instance"];};
    key = mkOption {type = localKeyType;};
    reject_slot_collisions = mkOption {type = moduleTypes.bool;};
    merge_contract = mkOption {
      type = moduleTypes.nullOr digestType;
    };
    controller_group = mkOption {type = localKeyType;};
  };

  authoredOutputType = strictSubmodule {
    description = mkOption {
      type = moduleTypes.nullOr descriptionType;
      default = null;
    };
    schema = mkOption {type = portableType;};
    phase = mkOption {type = moduleTypes.enum ["planning" "runtime"];};
    visibility = mkOption {type = moduleTypes.enum ["public" "protected"];};
    lifetime = mkOption {type = lifetimeType;};
  };

  authoredOutcomeType = strictSubmodule {
    completionEvidence = mkOption {type = portableType;};
    observationEvidence = mkOption {type = portableType;};
    supportsRejectedBeforeEffect = mkOption {type = moduleTypes.bool;};
    indeterminate = mkOption {
      type = moduleTypes.enum ["reconcile" "intervention-required"];
    };
  };

  authoredMethodType = strictSubmodule {
    description = mkOption {
      type = moduleTypes.nullOr descriptionType;
      default = null;
    };
    semantics = mkOption {type = authoredMethodSemanticsType;};
    parameters = mkOption {type = portableType;};
    targetResource = mkOption {type = qualifiedNameType;};
    outputs = mkOption {
      type = moduleTypes.attrsOf authoredOutputType;
      default = {};
    };
    permittedOperations = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
    };
    guarantees = mkOption {
      type = moduleTypes.listOf guaranteeType;
      default = [];
    };
    outcome = mkOption {type = authoredOutcomeType;};
  };

  authoredLifecycleType = strictSubmodule {
    stableResourceIdentity = mkOption {type = moduleTypes.bool;};
    releasesEphemeralOnDisable = mkOption {type = moduleTypes.bool;};
    retainsPersistentByDefault = mkOption {type = moduleTypes.bool;};
    persistentDeleteMethod = mkOption {
      type = moduleTypes.nullOr localKeyType;
      default = null;
    };
  };

  authoredAggregationType = strictSubmodule {
    scope = mkOption {type = moduleTypes.enum ["provider-instance"];};
    key = mkOption {type = localKeyType;};
    rejectSlotCollisions = mkOption {type = moduleTypes.bool;};
    mergeContract = mkOption {
      type = moduleTypes.nullOr digestType;
      default = null;
    };
    controllerGroup = mkOption {type = localKeyType;};
  };

  interfaceDeclarationBaseType = strictSubmodule {
    _legacy = mkOption {
      type = moduleTypes.bool;
      default = false;
      internal = true;
    };
    description = mkOption {
      type = moduleTypes.nullOr descriptionType;
      default = null;
    };
    name = mkOption {type = qualifiedNameType;};
    abi = mkOption {type = positiveU32Type;};
    requestType = mkOption {type = portableType;};
    configurationType = mkOption {
      type = moduleTypes.nullOr portableType;
      default = null;
    };
    outputs = mkOption {
      type = moduleTypes.attrsOf authoredOutputType;
      default = {};
    };
    methods = mkOption {
      type = moduleTypes.attrsOf authoredMethodType;
      default = {};
    };
    lifecycle = mkOption {type = authoredLifecycleType;};
    aggregation = mkOption {type = authoredAggregationType;};
    guarantees = mkOption {
      type = moduleTypes.listOf guaranteeType;
      default = [];
    };
    requiredFeatures = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
    };
  };
  interfaceDeclarationType = checkedSubmodule "ability interface declaration" interfaceDeclarationBaseType (declaration:
    declaration._legacy
    || (
      declaration.description
      != null
      && builtins.all (output: output.description != null) (builtins.attrValues declaration.outputs)
      && builtins.all (method:
        method.description
        != null
        && builtins.all (output: output.description != null) (builtins.attrValues method.outputs))
      (builtins.attrValues declaration.methods)
    ));

  projectedRequirementType = strictSubmodule {
    alias = mkOption {type = localKeyType;};
    accepted_interfaces = mkOption {type = moduleTypes.listOf interfaceKeyType;};
    methods = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
    };
    guarantees = mkOption {
      type = moduleTypes.listOf guaranteeType;
      default = [];
    };
    strength = mkOption {
      type = moduleTypes.enum ["required" "advisory"];
      default = "required";
    };
    fallback = mkOption {
      type = moduleTypes.nullOr (strictSubmodule {
        outputs = mkOption {
          type = moduleTypes.attrsOf canonicalValueType;
          default = {};
        };
      });
    };
  };

  interfaceDocumentType = strictSubmodule {
    schema = mkOption {type = moduleTypes.enum ["aos.ability.interface/v1"];};
    required_features = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
    };
    interface = mkOption {
      type = strictSubmodule {
        name = mkOption {type = qualifiedNameType;};
        abi = mkOption {type = positiveU32Type;};
        request = mkOption {type = portableSchemaType;};
        configuration = mkOption {
          type = moduleTypes.nullOr portableSchemaType;
          default = null;
        };
        outputs = mkOption {
          type = moduleTypes.attrsOf projectedOutputType;
          default = {};
        };
        methods = mkOption {
          type = moduleTypes.attrsOf projectedMethodType;
          default = {};
        };
        lifecycle = mkOption {type = projectedLifecycleType;};
        aggregation = mkOption {type = projectedAggregationType;};
        guarantees = mkOption {
          type = moduleTypes.listOf guaranteeType;
          default = [];
        };
      };
      apply = value:
        if value.configuration == null
        then builtins.removeAttrs value ["configuration"]
        else value;
    };
  };

  configuredInterfaces =
    if config == null
    then {}
    else config.aos.abilities.interfaces;
  interfacesNamed = name: abi:
    builtins.filter (
      declaration:
        declaration.name
        == name
        && declaration.abi == abi
    ) (builtins.attrValues configuredInterfaces);
  uniqueInterfaceDeclarations = declarations:
    builtins.attrValues (builtins.listToAttrs (builtins.map (declaration: let
        identity = interfaceIdentity (interfaceDocumentFromDeclaration declaration);
      in {
        name = builtins.toJSON identity;
        value = declaration;
      })
      declarations));
  interfacesMatchingRequirement = requirement:
    uniqueInterfaceDeclarations (builtins.filter (declaration: let
      identity = interfaceIdentity (interfaceDocumentFromDeclaration declaration);
    in
      identity.name
      == requirement.interface
      && identity.abi == requirement.abi
      && identity.descriptor == requirement.descriptor)
    (builtins.attrValues configuredInterfaces));
  typeAccepts = optionType: value:
    (builtins.tryEval (builtins.deepSeq
      (evalModules {
        modules = [
          {
            options.value = mkOption {type = optionType;};
            config.value = value;
          }
        ];
      }).config.value
      true)).success;

  handlerType = strictSubmodule {
    artifact = mkOption {
      type = packageOutputType;
      description = "Symbolic package artifact containing the handler executable.";
    };
    entryPoint = mkOption {
      type = relativePathType;
      description = "Relative executable path within the selected artifact.";
    };
    arguments = mkOption {
      type = portableType;
      description = "Portable option type for the handler argument document.";
    };
    result = mkOption {
      type = portableType;
      description = "Portable option type for the handler result document.";
    };
  };

  providerModuleType = strictSubmodule {
    artifact = mkOption {
      type = packageOutputType;
      description = "Symbolic package output containing the provider module.";
    };
    path = mkOption {
      type = relativePathType;
      description = "Relative Nix module path within the selected artifact.";
    };
  };

  implementationBaseType = strictSubmodule {
    _legacy = mkOption {
      type = moduleTypes.bool;
      default = false;
      internal = true;
    };
    description = mkOption {
      type = moduleTypes.nullOr descriptionType;
      default = null;
    };
    package = mkOption {
      type = moduleTypes.nullOr packageNameType;
      default = null;
      internal = true;
      description = "Owning package injected by the package ability carrier.";
    };
    interface = mkOption {
      type = declarationKeyType;
      description = "Package-local alias of the provider-neutral interface declaration.";
    };
    requirements = mkOption {
      type = moduleTypes.attrsOf projectedRequirementType;
      default = {};
      description = "Provider dependencies on other exact interfaces.";
    };
    methods = mkOption {
      type = moduleTypes.listOf localKeyType;
      description = "Exact interface methods supported by this implementation.";
    };
    guarantees = mkOption {
      type = moduleTypes.listOf guaranteeType;
      default = [];
      description = "Exact interface guarantees supplied by this implementation.";
    };
    state_format = mkOption {
      type = moduleTypes.nullOr digestType;
      default = null;
    };
    compose = mkOption {
      type = moduleTypes.nullOr functionType;
      default = null;
    };
    transition = mkOption {
      type = moduleTypes.nullOr functionType;
      default = null;
    };
    provide = mkOption {
      type = moduleTypes.nullOr functionType;
      default = null;
    };
    artifact = mkOption {
      type = moduleTypes.nullOr packageOutputType;
      default = null;
      internal = true;
      description = "Symbolic package output containing this implementation.";
    };
    artifacts = mkOption {
      type = moduleTypes.listOf packageOutputType;
      default = [];
      internal = true;
      description = "Additional symbolic package artifacts retained by this implementation.";
    };
    handlerDescriptor = mkOption {
      type = moduleTypes.nullOr handlerType;
      default = null;
      description = "Executable handler selected by a terminal implementation.";
    };
    providerModule = mkOption {
      type = moduleTypes.nullOr providerModuleType;
      default = null;
      description = "Provider module imported only when this implementation is selected.";
    };
    desiredType = mkOption {
      type = moduleTypes.nullOr portableType;
      default = null;
      description = "Provider realization value accepted after this implementation is selected.";
    };
    requiredFeatures = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
      description = "Runtime features required to admit this implementation.";
    };
  };
  implementationType = checkedSubmodule "ability implementation" implementationBaseType (implementation:
    (implementation._legacy || implementation.description != null)
    && (implementation.artifact == null || packageOutputType.check implementation.artifact)
    && builtins.all packageOutputType.check implementation.artifacts
    && (
      implementation.handlerDescriptor
      == null
      || (
        packageOutputType.check implementation.handlerDescriptor.artifact
        && relativePathType.check implementation.handlerDescriptor.entryPoint
        && portableType.check implementation.handlerDescriptor.arguments
        && portableType.check implementation.handlerDescriptor.result
      )
    )
    && (
      implementation.providerModule
      == null
      || (
        packageOutputType.check implementation.providerModule.artifact
        && relativePathType.check implementation.providerModule.path
      )
    )
    && (
      config
      == null
      || (
        builtins.hasAttr implementation.interface configuredInterfaces
        && (let
          declaration = configuredInterfaces.${implementation.interface};
        in
          uniqueValues implementation.methods
          && uniqueValues implementation.guarantees
          && builtins.all (method: builtins.hasAttr method declaration.methods) implementation.methods
          && builtins.all (guarantee: builtins.elem guarantee declaration.guarantees) implementation.guarantees)
      )
    ));

  guaranteeType = strictSubmodule {
    name = mkOption {
      type = qualifiedNameType;
      description = "Provider-neutral guarantee name.";
    };
    version = mkOption {
      type = positiveU32Type;
      description = "Guarantee version.";
    };
    descriptor = mkOption {
      type = digestType;
      description = "Exact semantic guarantee descriptor.";
    };
  };

  requirementBaseType = strictSubmodule {
    description = mkOption {
      type = descriptionType;
    };
    interface = mkOption {
      type = qualifiedNameType;
      description = "Provider-neutral interface name.";
    };
    abi = mkOption {
      type = positiveU32Type;
      description = "Required interface ABI.";
    };
    descriptor = mkOption {
      type = digestType;
      description = "Exact accepted interface descriptor.";
    };
    methods = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
      description = "Interface methods the consumer may invoke.";
    };
    guarantees = mkOption {
      type = moduleTypes.listOf guaranteeType;
      default = [];
      description = "Guarantees the selected implementation must provide.";
    };
    strength = mkOption {
      type = moduleTypes.enum ["required" "advisory"];
      default = "required";
      description = "Whether failure to bind prevents activation.";
    };
    fallback = mkOption {
      type = moduleTypes.nullOr (strictSubmodule {
        outputs = mkOption {
          type = moduleTypes.attrsOf canonicalValueType;
          default = {};
        };
      });
      default = null;
      description = "Typed fallback outputs for an advisory requirement.";
    };
  };
  requirementAccepted = requirement: let
    matches = interfacesMatchingRequirement requirement;
    fallbackAccepted = declaration:
      requirement.fallback
      == null
      || builtins.all (
        name:
          builtins.hasAttr name declaration.outputs
          && typeAccepts declaration.outputs.${name}.schema requirement.fallback.outputs.${name}
      ) (builtins.attrNames requirement.fallback.outputs);
    surfaceAccepted = declaration:
      uniqueValues requirement.methods
      && uniqueValues requirement.guarantees
      && builtins.all (method: builtins.hasAttr method declaration.methods) requirement.methods
      && builtins.all (guarantee: builtins.elem guarantee declaration.guarantees) requirement.guarantees;
  in
    config
    == null
    || (
      if matches == []
      then config.aos.abilities.environment == null
      else
        builtins.length matches
        == 1
        && fallbackAccepted (builtins.head matches)
        && surfaceAccepted (builtins.head matches)
    );

  environmentType = abilityTypes.environmentId;

  instanceBaseType = strictSubmodule {
    implementation = mkOption {
      type = moduleTypes.nullOr declarationKeyType;
      default = null;
      description = "Package implementation declaration instantiated here.";
    };
    configuration = mkOption {
      type = canonicalValueType;
      default = {};
      description = "Provider configuration checked against the interface type.";
    };
  };
  instanceAccepted = instance:
    if instance.implementation == null
    then instance.configuration == {}
    else if config == null || !(builtins.hasAttr instance.implementation config.aos.abilities.implementations)
    then config == null
    else let
      implementation = config.aos.abilities.implementations.${instance.implementation};
      configurationType = config.aos.abilities.interfaces.${implementation.interface}.configurationType;
    in
      if configurationType == null
      then instance.configuration == {}
      else typeAccepts configurationType instance.configuration;

  requestBaseType = strictSubmodule {
    package = mkOption {
      type = moduleTypes.nullOr packageNameType;
      default = null;
      internal = true;
      description = "Owning package injected by the package ability carrier.";
    };
    requirement = mkOption {
      type = declarationKeyType;
      description = "Package requirement template instantiated by this request.";
    };
    consumer = mkOption {
      type = declarationKeyType;
      description = "Qualified logical consumer instance declaration.";
    };
    scope = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
      description = "Composition scope below the consumer.";
    };
    parameters = mkOption {
      type = canonicalValueType;
      description = "Request value checked against the referenced interface type.";
    };
  };
  requestAccepted = request:
    if
      config
      == null
      || !(builtins.hasAttr request.requirement config.aos.abilities.requirementTemplates)
      || !(builtins.hasAttr request.consumer config.aos.abilities.instances)
    then config == null
    else let
      requirement = config.aos.abilities.requirementTemplates.${request.requirement};
      matches = interfacesMatchingRequirement requirement;
    in
      if matches == []
      then config.aos.abilities.environment == null
      else
        builtins.length matches
        == 1
        && typeAccepts (builtins.head matches).requestType request.parameters;

  bindingType = strictSubmodule {
    request = mkOption {
      type = declarationKeyType;
      description = "Concrete request selected by this binding.";
    };
    implementation = mkOption {
      type = declarationKeyType;
      description = "Selected package implementation declaration.";
    };
    providerInstance = mkOption {
      type = declarationKeyType;
      description = "Qualified selected provider instance declaration.";
    };
    slot = mkOption {
      type = localKeyType;
      description = "Authorized aggregation slot.";
    };
  };

  desiredResourceBaseType = strictSubmodule {
    kind = mkOption {
      type = qualifiedNameType;
      description = "Provider-neutral resource kind.";
    };
    controller = mkOption {
      type = declarationKeyType;
      description = "Binding that exclusively controls this resource.";
    };
    lifetime = mkOption {
      type = lifetimeType;
      description = "Retention lifetime declared by the owning interface.";
    };
    value = mkOption {
      type = canonicalValueType;
      description = "Provider-neutral desired value checked against the resource interface type.";
    };
    realization = mkOption {
      type = canonicalValueType;
      description = "Provider-owned realization checked against the selected implementation type.";
    };
  };
  desiredResourceAccepted = resource:
    if config == null
    then true
    else if !(builtins.hasAttr resource.controller config.aos.abilities.bindings)
    then false
    else let
      binding = config.aos.abilities.bindings.${resource.controller};
    in
      if !(builtins.hasAttr binding.implementation config.aos.abilities.implementations)
      then false
      else let
        implementation = config.aos.abilities.implementations.${binding.implementation};
        controllerDeclaration = config.aos.abilities.interfaces.${implementation.interface};
        resourceDeclarations = uniqueInterfaceDeclarations (builtins.filter
          (declaration: declaration.name == resource.kind)
          (builtins.attrValues configuredInterfaces));
        controlsKind =
          builtins.any
          (method:
            builtins.hasAttr method controllerDeclaration.methods
            && controllerDeclaration.methods.${method}.targetResource == resource.kind)
          implementation.methods;
        resourceDeclaration =
          if builtins.length resourceDeclarations == 1
          then builtins.head resourceDeclarations
          else null;
        lifetimeAllowed =
          resourceDeclaration
          != null
          && (
            resource.lifetime
            != "persistent"
            || resourceDeclaration.lifecycle.retainsPersistentByDefault
            || resourceDeclaration.lifecycle.persistentDeleteMethod != null
          );
      in
        resourceDeclaration
        != null
        && controlsKind
        && lifetimeAllowed
        && typeAccepts resourceDeclaration.requestType resource.value
        && implementation.desiredType != null
        && typeAccepts implementation.desiredType resource.realization;
in {
  options.aos.abilities = {
    environment = mkOption {
      type = moduleTypes.nullOr environmentType;
      default = null;
      internal = true;
      description = "Deployment-owned environment identity, absent during static package projection.";
    };
    interfaces = mkOption {
      type = abilityMapType "interfaces" interfaceDeclarationType;
      default = {};
      contributable = true;
      apply = interfaces: let
        declaredNames = builtins.map (declaration: declaration.name) (builtins.attrValues interfaces);
        targetsExist = builtins.all (declaration:
          builtins.all (method: builtins.elem method.targetResource declaredNames)
          (builtins.attrValues declaration.methods))
        (builtins.attrValues interfaces);
      in
        if config == null || config.aos.abilities.environment == null || targetsExist
        then interfaces
        else throw "An ability method targets an interface that is absent from the final fixed point.";
      description = "Provider-neutral interface declarations available independently of implementations.";
    };
    implementations = mkOption {
      type = abilityMapType "implementations" implementationType;
      default = {};
      contributable = true;
      description = "Package-owned ability implementations available to provider discovery.";
    };
    requirementTemplates = mkOption {
      type = abilityMapType "requirementTemplates" requirementBaseType;
      default = {};
      contributable = true;
      apply = requirements:
        if builtins.all requirementAccepted (builtins.attrValues requirements)
        then requirements
        else throw "An ability requirement fallback does not match its declared interface output type.";
      description = "Package-owned ability requirements available to configured instances.";
    };
    instances = mkOption {
      type = abilityMapType "instances" instanceBaseType;
      default = {};
      contributable = true;
      apply = instances:
        if
          (instances == {} || config == null || config.aos.abilities.environment != null)
          && builtins.all instanceAccepted (builtins.attrValues instances)
        then instances
        else throw "Ability instances require a deployment environment and valid implementation configuration.";
      description = "Configured logical provider and consumer instances.";
    };
    requests = mkOption {
      type = abilityMapType "requests" requestBaseType;
      default = {};
      contributable = true;
      apply = requests:
        if builtins.all requestAccepted (builtins.attrValues requests)
        then requests
        else throw "An ability request does not match its requirement interface request type.";
      description = "Concrete ability requests emitted by configured instances.";
    };
    bindings = mkOption {
      type = abilityMapType "bindings" bindingType;
      default = {};
      description = "Deployment-owned exact provider selections and grants.";
    };
    desiredResources = mkOption {
      type = abilityMapType "desiredResources" desiredResourceBaseType;
      default = {};
      apply = resources:
        if builtins.all desiredResourceAccepted (builtins.attrValues resources)
        then resources
        else throw "A desired ability resource does not match its declared interface request type.";
      description = "Provider-owned desired resources derived during module evaluation.";
    };
  };
}
