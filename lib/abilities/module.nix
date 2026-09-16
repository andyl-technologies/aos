##! Canonical ability options for the AOS module fixed point.
##!
##! This module owns the shared containers and canonical core interfaces.
##! Packages contribute implementations and package-specific declarations
##! through ordinary modules, and semantic validation resolves references
##! after the complete fixed point evaluates.
{
  config ? null,
  mkOption,
  moduleTypes,
  abilityTypes,
  schemas,
  evalModules,
  guaranteeIdentity,
  identityKeyFor,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
  normalizeSemanticValue,
  resourceRevision,
  coreInterfaceModule,
  normalizePackageOutputSelectors,
}: let
  strictSubmodule = options:
    moduleTypes.submodule {
      _file = "<lib.abilities.module>";
      config._module.strict = true;
      inherit options;
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
    <= abilityTypes.limits.maxStructuralDepth
    && (
      value
      == null
      || builtins.isBool value
      || (
        builtins.isInt value
        && value >= -abilityTypes.limits.maxSafeInteger
        && value <= abilityTypes.limits.maxSafeInteger
      )
      || (
        builtins.isString value
        && builtins.stringLength value <= abilityTypes.limits.maxStringLength
      )
      || (builtins.isList value && builtins.all (isCanonicalValue (depth + 1)) value)
      || (
        builtins.isAttrs value
        && builtins.all (
          name:
            builtins.stringLength name
            <= abilityTypes.limits.maxStringLength
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
  guaranteeTextType = checkedType "guarantee text" "non-empty control-free guarantee text" (value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= abilityTypes.limits.maxStringLength
    && builtins.match "[^[:cntrl:]]+" value != null);

  packageForDefinition = definition:
    if builtins.match "package:.+" (definition.provenance or "") == null
    then null
    else builtins.substring 8 (builtins.stringLength definition.provenance - 8) definition.provenance;
  qualify = package: name:
    if package == null
    then name
    else "${package}:${name}";
  qualifyReference = package: name:
    if package == null || declarationKeyType.check name
    then name
    else qualify package name;
  qualifyGuarantees = package: guarantees:
    builtins.map (guarantee:
      if builtins.isString guarantee
      then
        if declarationKeyType.check guarantee
        then guarantee
        else qualify package guarantee
      else guarantee)
    guarantees;
  qualifyRequirementGuarantees = package: requirement:
    requirement // {guarantees = qualifyGuarantees package (requirement.guarantees or []);};
  qualifyInterfaceGuarantees = package: interface:
    interface
    // {
      guarantees = qualifyGuarantees package (interface.guarantees or []);
      methods = builtins.mapAttrs (_: method:
        method // {guarantees = qualifyGuarantees package (method.guarantees or []);})
      (interface.methods or {});
    };
  qualifyImplementationGuarantees = package: implementation:
    implementation
    // {
      guarantees = qualifyGuarantees package (implementation.guarantees or []);
      requirements = builtins.mapAttrs (_: qualifyRequirementGuarantees package) (implementation.requirements or {});
    };
  qualifyDeferredResults = package: value:
    if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then
      value
      // {
        request =
          if declarationKeyType.check value.request
          then value.request
          else qualify package value.request;
      }
    else if builtins.isAttrs value
    then builtins.mapAttrs (_: qualifyDeferredResults package) value
    else if builtins.isList value
    then builtins.map (qualifyDeferredResults package) value
    else value;
  qualifyAbilityValue = collection: package: localKey: value:
    if package == null
    then value
    else if collection == "interfaces"
    then
      qualifyInterfaceGuarantees package value
      // {
        package = package;
        inherit localKey;
      }
    else if collection == "guarantees"
    then
      value
      // {
        package = package;
        inherit localKey;
      }
    else if collection == "implementations"
    then
      (normalizePackageOutputSelectors {
        owner = package;
        value = qualifyImplementationGuarantees package value;
      })
      // {
        package = package;
        inherit localKey;
      }
      // (
        if value ? interface
        then {
          interface =
            if builtins.isString value.interface
            then
              if declarationKeyType.check value.interface || builtins.hasAttr value.interface config.aos.abilities.interfaces
              then value.interface
              else qualify package value.interface
            else value.interface;
        }
        else {}
      )
    else if collection == "instances"
    then
      (normalizePackageOutputSelectors {
        owner = package;
        value = qualifyDeferredResults package value;
      })
      // {
        package = package;
        inherit localKey;
      }
      // (
        if !(value ? implementation)
        then {}
        else {
          implementation =
            if value.implementation == null
            then null
            else qualifyReference package value.implementation;
        }
      )
    else if collection == "requests"
    then
      (normalizePackageOutputSelectors {
        owner = package;
        value = qualifyDeferredResults package value;
      })
      // {
        package = package;
        inherit localKey;
      }
      // (
        if value ? requirement
        then {requirement = qualifyReference package value.requirement;}
        else {}
      )
      // (
        if value ? consumer
        then {consumer = qualifyReference package value.consumer;}
        else {}
      )
    else if collection == "requirementTemplates"
    then
      qualifyRequirementGuarantees package value
      // {
        package = package;
        inherit localKey;
      }
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
                value = qualifyAbilityValue collection package name definition.value.${name};
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

  localKeyType = abilityTypes.localKey;
  packageNameType = abilityTypes.packageName;
  declarationKeyType = abilityTypes.declarationKey;
  packageOutputType = abilityTypes.packageOutputSelector;
  relativePathType = abilityTypes.relativePath;
  qualifiedNameType = abilityTypes.qualifiedName;
  digestType = abilityTypes.digest;
  positiveU32Type = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxU32;
  };
  canonicalRequirementListType = element:
    abilityTypes.list {
      inherit element;
      maxItems = abilityTypes.limits.maxCollectionItems;
      unique = true;
      canonicalOrder = true;
    };
  stageType = abilityTypes.stage;
  valuePhaseType = abilityTypes.valuePhase;
  lifetimeType = abilityTypes.lifetime;

  interfaceKeyType = abilityTypes.interfaceKey;
  implementationInterfaceType = moduleTypes.either localKeyType (moduleTypes.either declarationKeyType interfaceKeyType);
  interfaceSelectorType = strictSubmodule {
    name = mkOption {type = qualifiedNameType;};
    abi = mkOption {type = positiveU32Type;};
    descriptor = mkOption {
      type = moduleTypes.nullOr digestType;
      default = null;
    };
  };
  uniqueValues = values:
    builtins.length values
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = identityKeyFor "aos.ability.canonical-value-key/v1" value;
        value = true;
      })
      values)));

  projectedOutputType = strictSubmodule {
    description = mkOption {
      type = descriptionType;
      description = "Signed output documentation excluded from semantic identity.";
    };
    schema = mkOption {
      type = portableSchemaType;
      description = "Portable output value schema projected from its authored option type.";
    };
    phase = mkOption {
      type = valuePhaseType;
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
    description = mkOption {
      type = descriptionType;
      description = "Signed method documentation excluded from semantic identity.";
    };
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
      type = moduleTypes.listOf guaranteeKeyType;
      default = [];
      description = "Guarantees promised by the method.";
    };
    outcome = mkOption {
      type = projectedOutcomeType;
      description = "Completion and reconciliation semantics.";
    };
  };

  projectedLifecycleType = strictSubmodule {
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
    phase = mkOption {type = valuePhaseType;};
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
      type = canonicalRequirementListType guaranteeReferenceType;
      default = [];
    };
    outcome = mkOption {type = authoredOutcomeType;};
  };

  authoredLifecycleType = strictSubmodule {
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
    package = mkOption {
      type = moduleTypes.nullOr packageNameType;
      default = null;
      internal = true;
      description = "Owning package injected by the package ability carrier.";
    };
    localKey = mkOption {
      type = moduleTypes.nullOr localKeyType;
      default = null;
      internal = true;
      description = "Package-local declaration key injected by the package ability carrier.";
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
      type = canonicalRequirementListType guaranteeReferenceType;
      default = [];
    };
    requiredFeatures = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
    };
  };
  interfaceDeclarationType = checkedSubmodule "ability interface declaration" interfaceDeclarationBaseType (declaration:
    declaration.description
    != null
    && builtins.all (output: output.description != null) (builtins.attrValues declaration.outputs)
    && builtins.all (method:
      method.description
      != null
      && builtins.all (output: output.description != null) (builtins.attrValues method.outputs))
    (builtins.attrValues declaration.methods));

  projectedRequirementType = strictSubmodule {
    alias = mkOption {type = localKeyType;};
    description = mkOption {
      type = descriptionType;
      description = "Authenticated requirement documentation retained with its exact contract.";
    };
    accepted_interfaces = mkOption {type = moduleTypes.listOf interfaceSelectorType;};
    methods = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
    };
    guarantees = mkOption {
      type = moduleTypes.listOf guaranteeKeyType;
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

  implementationRequirementType = strictSubmodule {
    alias = mkOption {type = localKeyType;};
    description = mkOption {
      type = descriptionType;
      description = "Signed requirement documentation excluded from semantic identity.";
    };
    accepted_interfaces = mkOption {type = moduleTypes.listOf interfaceSelectorType;};
    methods = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
    };
    guarantees = mkOption {
      type = canonicalRequirementListType guaranteeReferenceType;
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
        description = mkOption {type = descriptionType;};
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
          type = moduleTypes.listOf guaranteeKeyType;
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
  configuredGuarantees =
    if config == null
    then {}
    else config.aos.abilities.guarantees;
  guaranteeForReference = context: reference:
    if !builtins.isString reference
    then throw "${context} must use an exact guarantee declaration alias."
    else if builtins.hasAttr reference configuredGuarantees
    then guaranteeIdentity configuredGuarantees.${reference}
    else throw "${context} references absent guarantee declaration '${reference}'.";
  semanticInterfaceDeclaration = context: declaration:
    declaration
    // {
      guarantees =
        builtins.map
        (guarantee: guaranteeForReference "${context} guarantee" guarantee)
        declaration.guarantees;
      methods = builtins.mapAttrs (methodName: method:
        method
        // {
          guarantees =
            builtins.map
            (guarantee: guaranteeForReference "${context} method '${methodName}' guarantee" guarantee)
            method.guarantees;
        })
      declaration.methods;
    };
  interfaceIdentityForDeclaration = context: declaration:
    interfaceIdentity (
      interfaceDocumentFromDeclaration (semanticInterfaceDeclaration context declaration)
    );
  interfaceDeclarationForReference = context: reference:
    if builtins.isString reference
    then configuredInterfaces.${reference} or (throw "${context} references absent interface declaration '${reference}'.")
    else let
      matches = builtins.filter (declaration:
        interfaceIdentityForDeclaration context declaration == reference)
      (builtins.attrValues configuredInterfaces);
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "${context} must resolve its exact shared interface identity to one declaration.";
  interfacesNamed = name: abi:
    builtins.filter (
      declaration:
        declaration.name
        == name
        && declaration.abi == abi
    ) (builtins.attrValues configuredInterfaces);
  uniqueInterfaceDeclarations = declarations:
    builtins.attrValues (builtins.listToAttrs (builtins.map (declaration: let
        identity = interfaceIdentityForDeclaration "interface declaration" declaration;
      in {
        name = identityKeyFor "aos.ability.interface-catalog-key/v1" identity;
        value = declaration;
      })
      declarations));
  interfacesMatchingRequirement = requirement:
    uniqueInterfaceDeclarations (builtins.filter (declaration: let
      identity = interfaceIdentityForDeclaration "requirement interface" declaration;
      selectorMatches = selector:
        identity.name
        == selector.name
        && identity.abi == selector.abi
        && (selector.descriptor == null || identity.descriptor == selector.descriptor);
    in
      if requirement ? accepted_interfaces
      then builtins.any selectorMatches requirement.accepted_interfaces
      else
        identity.name
        == requirement.interface
        && identity.abi == requirement.abi
        && (requirement.descriptor == null || identity.descriptor == requirement.descriptor))
    (builtins.attrValues configuredInterfaces));
  typeAccepts = optionType: value:
    abilityTypes.accepts "ability value" optionType value;

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

  qualificationType = strictSubmodule {
    adapter = mkOption {
      type = localKeyType;
      description = "Stable package-owned adapter identity used by qualification evidence.";
    };
    scope = mkOption {
      type = localKeyType;
      description = "Native execution scope containing this implementation's effects.";
    };
    observationKind = mkOption {
      type = localKeyType;
      description = "Typed observation record kind emitted by the package-owned observer.";
    };
    conformanceFamilies = mkOption {
      type = moduleTypes.listOf localKeyType;
      description = "Semantic conformance families required by this implementation.";
    };
    observer = mkOption {
      type = handlerType;
      description = "Package-owned executable that independently observes provider state.";
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
    description = mkOption {
      type = descriptionType;
      description = "Human-readable implementation documentation excluded from executable identity.";
    };
    package = mkOption {
      type = moduleTypes.nullOr packageNameType;
      default = null;
      internal = true;
      description = "Owning package injected by the package ability carrier.";
    };
    localKey = mkOption {
      type = moduleTypes.nullOr localKeyType;
      default = null;
      internal = true;
      description = "Package-local declaration key injected by the package ability carrier.";
    };
    interface = mkOption {
      type = implementationInterfaceType;
      description = "Package-local declaration alias or exact shared provider-neutral interface identity.";
    };
    requirements = mkOption {
      type = moduleTypes.attrsOf implementationRequirementType;
      default = {};
      description = "Provider dependencies on other exact interfaces.";
    };
    methods = mkOption {
      type = moduleTypes.listOf localKeyType;
      description = "Exact interface methods supported by this implementation.";
    };
    guarantees = mkOption {
      type = canonicalRequirementListType guaranteeReferenceType;
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
    compositionType = mkOption {
      type = moduleTypes.nullOr portableType;
      default = null;
      description = "Complete aggregated resource value accepted by this implementation's pure composer.";
    };
    requiredFeatures = mkOption {
      type = moduleTypes.listOf localKeyType;
      default = [];
      description = "Runtime features required to admit this implementation.";
    };
    qualification = mkOption {
      type = moduleTypes.nullOr qualificationType;
      default = null;
      description = "Package-owned native conformance and observation claim.";
    };
  };
  implementationType = checkedSubmodule "ability implementation" implementationBaseType (implementation:
    implementation.description
    != null
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
      implementation.qualification
      == null
      || (
        implementation.qualification.conformanceFamilies
        != []
        && uniqueValues implementation.qualification.conformanceFamilies
      )
    )
    && uniqueValues implementation.methods
    && uniqueValues implementation.guarantees);

  guaranteeType = abilityTypes.record {
    fields = {
      name = qualifiedNameType;
      version = positiveU32Type;
      descriptor = digestType;
    };
  };

  guaranteeKeyType = strictSubmodule {
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
  requirementGuaranteesType = canonicalRequirementListType guaranteeType;
  requirementGuaranteesSchema =
    abilityTypes.schemaOf "requirement guarantees" requirementGuaranteesType;

  guaranteeReferenceType =
    moduleTypes.addCheck moduleTypes.str (value:
      localKeyType.check value || declarationKeyType.check value);

  guaranteeDeclarationType = strictSubmodule {
    package = mkOption {
      type = moduleTypes.nullOr packageNameType;
      default = null;
      internal = true;
      description = "Owning package injected by the package ability carrier.";
    };
    localKey = mkOption {
      type = moduleTypes.nullOr localKeyType;
      default = null;
      internal = true;
      description = "Package-local declaration key injected by the package ability carrier.";
    };
    name = mkOption {
      type = qualifiedNameType;
      description = "Provider-neutral guarantee name.";
    };
    version = mkOption {
      type = positiveU32Type;
      description = "Guarantee version.";
    };
    semantics = mkOption {
      type = guaranteeTextType;
      description = "Canonical public meaning from which the guarantee descriptor is derived.";
    };
    description = mkOption {
      type = guaranteeTextType;
      description = "Human-readable guarantee documentation excluded from semantic identity.";
    };
  };

  requirementBaseType = strictSubmodule {
    package = mkOption {
      type = moduleTypes.nullOr packageNameType;
      default = null;
      internal = true;
      description = "Owning package injected by the package ability carrier.";
    };
    localKey = mkOption {
      type = moduleTypes.nullOr localKeyType;
      default = null;
      internal = true;
      description = "Package-local declaration key injected by the package ability carrier.";
    };
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
      type = moduleTypes.nullOr digestType;
      default = null;
      description = "Optional exact semantic pin for a package-owned interface.";
    };
    methods = mkOption {
      type = canonicalRequirementListType localKeyType;
      default = [];
      description = "Interface methods the consumer may invoke.";
    };
    guarantees = mkOption {
      type = canonicalRequirementListType guaranteeReferenceType;
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
  requirementAccepted = requirement:
    assert builtins.deepSeq requirementGuaranteesSchema true; let
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
  derivedInstanceKey = declaration: "instance-${identityKeyFor "aos.ability.instance-key/v1" {
    inherit declaration;
  }}";
  projectedInstanceIdentities =
    if config == null || config.aos.abilities.environment == null
    then {}
    else
      builtins.mapAttrs (declaration: _: {
        environment = config.aos.abilities.environment;
        key = derivedInstanceKey declaration;
      })
      config.aos.abilities.instances;

  instanceBaseType = strictSubmodule {
    package = mkOption {
      type = moduleTypes.nullOr packageNameType;
      default = null;
      internal = true;
      description = "Owning package injected by the package ability carrier.";
    };
    localKey = mkOption {
      type = moduleTypes.nullOr localKeyType;
      default = null;
      internal = true;
      description = "Package-local declaration key injected by the package ability carrier.";
    };
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
      declaration = interfaceDeclarationForReference "ability instance" implementation.interface;
      configurationType = declaration.configurationType;
    in
      if configurationType == null
      then instance.configuration == {}
      else typeAccepts configurationType instance.configuration;

  requestLifetime = request: let
    requirement =
      config.aos.abilities.requirementTemplates.${request.requirement}
      or (config.aos.abilities.compositionRequirements.${request.requirement}.requirement or null);
    matches =
      if requirement == null
      then []
      else interfacesMatchingRequirement requirement;
    interface =
      if builtins.length matches == 1
      then builtins.head matches
      else null;
    methodOutputs =
      if interface == null
      then []
      else
        builtins.concatMap
        (method:
          builtins.attrValues (
            interface.methods.${method}.outputs
            or (throw "Ability request method '${method}' has no interface contract.")
          ))
        requirement.methods;
    outputLifetimes = builtins.map (output: output.lifetime) (
      (
        if interface == null
        then []
        else builtins.attrValues interface.outputs
      )
      ++ methodOutputs
    );
    lifetimeRank = {
      attempt = 0;
      transaction = 1;
      instance = 2;
      persistent = 3;
    };
    longerLifetime = current: candidate:
      if lifetimeRank.${candidate} > lifetimeRank.${current}
      then candidate
      else current;
  in
    if outputLifetimes == []
    then throw "Ability request '${request.requirement}' has no selected interface output lifetime."
    else builtins.foldl' longerLifetime "attempt" outputLifetimes;

  normalizeRequest = request: let
    requirement =
      config.aos.abilities.requirementTemplates.${request.requirement}
      or (config.aos.abilities.compositionRequirements.${request.requirement}.requirement or null);
    matches =
      if requirement == null
      then []
      else interfacesMatchingRequirement requirement;
    interface =
      if builtins.length matches == 1
      then builtins.head matches
      else throw "Ability request '${request.requirement}' does not select one exact interface.";
  in
    request
    // {
      parameters = abilityTypes.normalize "ability request parameters" interface.requestType request.parameters;
      lifetime = requestLifetime request;
    };

  requestBaseType = strictSubmodule {
    package = mkOption {
      type = moduleTypes.nullOr packageNameType;
      default = null;
      internal = true;
      description = "Owning package injected by the package ability carrier.";
    };
    localKey = mkOption {
      type = moduleTypes.nullOr localKeyType;
      default = null;
      internal = true;
      description = "Package-local declaration key injected by the package ability carrier.";
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
    lifetime = mkOption {
      type = moduleTypes.nullOr lifetimeType;
      default = null;
      internal = true;
      description = "Semantic lifetime derived from the selected interface method contract.";
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

  resourceIdentityType = strictSubmodule {
    provider = mkOption {
      type = abilityTypes.instanceId;
    };
    key = mkOption {
      type = localKeyType;
    };
  };

  desiredResourceBaseType = strictSubmodule {
    resource = mkOption {
      type = resourceIdentityType;
      description = "Exact logical resource identity emitted by provider composition.";
    };
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

  resolvedResourceType = strictSubmodule {
    resource = mkOption {
      type = resourceIdentityType;
      description = "Exact logical resource identity derived from its selected controller.";
    };
    kind = mkOption {
      type = qualifiedNameType;
    };
    controller = mkOption {
      type = moduleTypes.nullOr declarationKeyType;
      description = "Selected write controller, absent for a published read-only resource.";
    };
    lifetime = mkOption {
      type = lifetimeType;
    };
    value = mkOption {
      type = canonicalValueType;
    };
    realization = mkOption {
      type = canonicalValueType;
    };
    revision = mkOption {
      type = digestType;
      description = "Semantic revision of the complete selected resource projection.";
    };
  };

  semanticImplementation = name: implementation: let
    declaration = interfaceDeclarationForReference "implementation '${name}'" implementation.interface;
    normalizeHandler = handler:
      if handler == null
      then null
      else {
        artifact = handler.artifact;
        entry_point = handler.entryPoint;
        arguments = abilityTypes.schemaOf "handler arguments" handler.arguments;
        result = abilityTypes.schemaOf "handler result" handler.result;
      };
  in {
    declaration = name;
    package = implementation.package;
    interface = interfaceIdentityForDeclaration "implementation '${name}' interface" declaration;
    requirements = builtins.mapAttrs (requirementName: requirement:
      (builtins.removeAttrs requirement ["description"])
      // {
        guarantees =
          builtins.map
          (guarantee: guaranteeForReference "implementation '${name}' requirement '${requirementName}' guarantee" guarantee)
          requirement.guarantees;
      })
    implementation.requirements;
    guarantees =
      builtins.map
      (guarantee: guaranteeForReference "implementation '${name}' guarantee" guarantee)
      implementation.guarantees;
    inherit
      (implementation)
      methods
      state_format
      artifact
      artifacts
      providerModule
      requiredFeatures
      ;
    handler = normalizeHandler implementation.handlerDescriptor;
    desired_schema =
      if implementation.desiredType == null
      then null
      else abilityTypes.schemaOf "provider realization" implementation.desiredType;
    composition_schema =
      if implementation.compositionType == null
      then null
      else abilityTypes.schemaOf "provider composition resource" implementation.compositionType;
  };

  resolveResource = _: authored: let
    binding = config.aos.abilities.bindings.${authored.controller};
    providerDeclaration = binding.providerInstance;
    provider = config.aos.abilities.instances.${providerDeclaration};
    implementationName = binding.implementation;
    implementation = config.aos.abilities.implementations.${implementationName};
    resource = authored.resource;
    selected = {
      schema = "aos.ability.selected-resource/v1";
      instance = {
        inherit providerDeclaration;
        identity = resource.provider;
        configuration = provider.configuration;
      };
      controller = {
        binding = authored.controller;
        inherit (binding) slot;
      };
      implementation = semanticImplementation implementationName implementation;
      resource = {
        inherit resource;
        inherit (authored) kind controller lifetime value realization;
      };
    };
  in {
    inherit resource;
    inherit (authored) kind controller lifetime value realization;
    revision = resourceRevision (normalizeSemanticValue selected);
  };

  resourceIdentityKey = resource:
    identityKeyFor "aos.ability.resource-id-key/v1" resource;

  bindingForPublishedRequest = requestName: let
    matching =
      builtins.filter
      (name: config.aos.abilities.bindings.${name}.request == requestName)
      (builtins.attrNames config.aos.abilities.bindings);
  in
    if builtins.length matching == 1
    then {
      name = builtins.head matching;
      value = config.aos.abilities.bindings.${builtins.head matching};
    }
    else throw "Published resource output '${requestName}' must have exactly one selected binding.";

  resolvePublishedResource = requestName: output: let
    reference = output.value;
    binding = bindingForPublishedRequest requestName;
    implementation = config.aos.abilities.implementations.${binding.value.implementation};
    declaration = config.aos.abilities.interfaces.${implementation.interface};
    request =
      config.aos.abilities.requests.${requestName}
      or config.aos.abilities.compositionRequests.${requestName}
      or (throw "Published resource output '${requestName}' has no exact request declaration.");
    normalizedRequest =
      (evalModules {
        modules = [
          {
            options.value = mkOption {type = declaration.requestType;};
            config.value = request.parameters;
          }
        ];
      }).config.value;
    selectedImplementation = semanticImplementation binding.value.implementation implementation;
    publication = {
      schema = "aos.ability.resource-publication/v1";
      inherit (reference) interface resource operations lifetime;
      implementation = selectedImplementation;
    };
    selected = {
      schema = "aos.ability.selected-published-resource/v1";
      inherit publication;
      value = normalizedRequest;
      realization = null;
    };
  in {
    inherit (reference) resource lifetime;
    kind = reference.interface.name;
    controller = null;
    value = normalizedRequest;
    realization = null;
    revision = resourceRevision (normalizeSemanticValue selected);
  };

  publishedResourceCandidates = builtins.concatLists (builtins.map
    (requestName:
      builtins.concatLists (builtins.map
        (outputName: let
          output = config.aos.abilities.compositionOutputs.${requestName}.${outputName};
        in
          if abilityTypes.resourceReference.check output.value
          then [(resolvePublishedResource requestName output)]
          else [])
        (builtins.attrNames config.aos.abilities.compositionOutputs.${requestName})))
    (builtins.attrNames config.aos.abilities.compositionOutputs));

  resolvedResourceProjection = let
    desired = builtins.mapAttrs resolveResource config.aos.abilities.desiredResources;
    desiredValues = builtins.attrValues desired;
    desiredIdentities = builtins.map (entry: resourceIdentityKey entry.resource) desiredValues;
    uniqueDesiredIdentities = builtins.attrNames (builtins.listToAttrs (builtins.map (identity: {
        name = identity;
        value = true;
      })
      desiredIdentities));
    publicationGroups =
      builtins.foldl' (groups: publication: let
        identity = resourceIdentityKey publication.resource;
      in
        groups // {${identity} = (groups.${identity} or []) ++ [publication];})
      {}
      publishedResourceCandidates;
    observerOnly =
      builtins.filter
      (identity: !(builtins.elem identity desiredIdentities))
      (builtins.attrNames publicationGroups);
    checkedPublication = identity: let
      publications = publicationGroups.${identity};
      first = builtins.head publications;
    in
      if builtins.all (publication: publication == first) publications
      then first
      else throw "Published resource '${identity}' has conflicting declarations or implementations.";
    published = builtins.listToAttrs (builtins.map (identity: {
        name = "publication-${identity}";
        value = checkedPublication identity;
      })
      observerOnly);
  in
    if builtins.length desiredIdentities == builtins.length uniqueDesiredIdentities
    then desired // published
    else throw "Desired resources contain a duplicate logical ResourceId.";

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
        controllerDeclaration =
          interfaceDeclarationForReference
          "controller implementation '${binding.implementation}'"
          implementation.interface;
        resourceDeclarations = uniqueInterfaceDeclarations (builtins.filter
          (declaration: declaration.name == resource.kind)
          (builtins.attrValues configuredInterfaces));
        controlsKind =
          builtins.any
          (method:
            builtins.hasAttr method controllerDeclaration.methods
            && controllerDeclaration.methods.${method}.targetResource == resource.kind
            && controllerDeclaration.methods.${method}.semantics.requiredTargetAccess != "read")
          implementation.methods;
        resourceDeclaration =
          if builtins.length resourceDeclarations == 1
          then builtins.head resourceDeclarations
          else null;
        resourceType =
          if implementation.compositionType == null
          then resourceDeclaration.requestType
          else implementation.compositionType;
      in
        resourceDeclaration
        != null
        && resource.resource.provider == config.aos.abilities.instanceIdentities.${binding.providerInstance}
        && controlsKind
        && typeAccepts resourceType resource.value
        && implementation.desiredType != null
        && typeAccepts implementation.desiredType resource.realization;

  compositionOutputType = strictSubmodule {
    value = mkOption {
      type = canonicalValueType;
      description = "Typed provider output value.";
    };
    phase = mkOption {type = valuePhaseType;};
    visibility = mkOption {type = moduleTypes.enum ["public" "protected"];};
    lifetime = mkOption {type = lifetimeType;};
  };
  executionObserverSelectionType = strictSubmodule {
    request = mkOption {
      type = declarationKeyType;
      description = "Bound request whose provider publishes the observer inputs.";
    };
    resourceOutput = mkOption {
      type = localKeyType;
      description = "Protected retained-resource output from the observer provider.";
    };
    socketOutput = mkOption {
      type = localKeyType;
      description = "Protected planning-phase execution-path output for the observer socket.";
    };
  };
  resolvedExecutionObserver = let
    selected = config.aos.abilities.executionObserver;
    outputs =
      if selected == null
      then null
      else config.aos.abilities.compositionOutputs.${selected.request} or null;
    resource =
      if outputs == null
      then null
      else outputs.${selected.resourceOutput} or null;
    socket =
      if outputs == null
      then null
      else outputs.${selected.socketOutput} or null;
    protectedPlanningOutput = output:
      output
      != null
      && output.phase == "planning"
      && output.visibility == "protected";
  in
    if selected == null
    then null
    else if
      protectedPlanningOutput resource
      && protectedPlanningOutput socket
      && abilityTypes.resourceReference.check resource.value
      && abilityTypes.executionPath.check socket.value
      && builtins.elem resource.value.lifetime ["transaction" "instance" "persistent"]
    then {
      inherit (selected) request;
      resource = resource.value;
      socket = socket.value;
    }
    else throw "Execution observer selection must name protected planning outputs from one bound request.";
  compositionRequirementType = strictSubmodule {
    implementation = mkOption {type = declarationKeyType;};
    alias = mkOption {type = localKeyType;};
    requirement = mkOption {type = projectedRequirementType;};
  };
  compositionPendingRequestType = strictSubmodule {
    originGroup = mkOption {type = moduleTypes.str;};
    localRequestKey = mkOption {type = localKeyType;};
    implementation = mkOption {type = declarationKeyType;};
    providerInstance = mkOption {type = declarationKeyType;};
    requirement = mkOption {type = localKeyType;};
    slot = mkOption {type = localKeyType;};
    request = mkOption {type = declarationKeyType;};
    declaration = mkOption {type = requestBaseType;};
  };
  compositionPendingRequirementType = strictSubmodule {
    implementation = mkOption {
      type = declarationKeyType;
      description = "Exact selected implementation that activated these requirements.";
    };
    providerInstance = mkOption {
      type = declarationKeyType;
      description = "Exact selected provider instance that activated these requirements.";
    };
    requirements = mkOption {
      type = moduleTypes.listOf localKeyType;
      description = "Canonical declared requirement aliases activated for the next binding pass.";
    };
  };
in {
  imports = [./composition-driver.nix coreInterfaceModule];

  options.aos.abilities = {
    environment = mkOption {
      type = moduleTypes.nullOr environmentType;
      default = null;
      internal = true;
      description = "Deployment-owned environment identity, absent during static package projection.";
    };
    guarantees = mkOption {
      type = abilityMapType "guarantees" guaranteeDeclarationType;
      default = {};
      contributable = true;
      description = "Package-owned guarantee declarations keyed by their package-local alias.";
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
      apply = requirements: let
        rejected =
          builtins.filter
          (name: !requirementAccepted requirements.${name})
          (builtins.attrNames requirements);
      in
        if rejected == []
        then requirements
        else throw "Ability requirements do not match their declared interface contracts: ${builtins.concatStringsSep ", " rejected}.";
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
    instanceIdentities = mkOption {
      type = moduleTypes.attrsOf abilityTypes.instanceId;
      default = {};
      readOnly = true;
      internal = true;
      description = "Canonical deployment instance identities derived from final qualified declaration keys.";
    };
    requests = mkOption {
      type = abilityMapType "requests" requestBaseType;
      default = {};
      contributable = true;
      apply = requests: let
        normalized = builtins.mapAttrs (_: normalizeRequest) requests;
      in
        if builtins.all requestAccepted (builtins.attrValues requests)
        then normalized
        else let
          rejected = builtins.filter (name: !requestAccepted requests.${name}) (builtins.attrNames requests);
        in
          throw "Ability request(s) do not match their requirement interface request type: ${builtins.concatStringsSep ", " rejected}";
      description = "Concrete ability requests emitted by configured instances.";
    };
    bindings = mkOption {
      type = abilityMapType "bindings" bindingType;
      default = {};
      description = "Deployment-owned exact provider selections and grants.";
    };
    compositionOutputs = mkOption {
      type = moduleTypes.attrsOf (moduleTypes.attrsOf compositionOutputType);
      default = {};
      readOnly = true;
      internal = true;
      description = "Typed provider outputs derived for exact bound requests.";
    };
    executionObserver = mkOption {
      type = moduleTypes.nullOr executionObserverSelectionType;
      default = null;
      description = ''
        Selects the protected retained resource and socket path published by one
        package-owned observer provider. The final fixed point retains only the
        resolved typed outputs, never a path convention.
      '';
    };
    resolvedExecutionObserver = mkOption {
      type = moduleTypes.nullOr moduleTypes.attrs;
      default = resolvedExecutionObserver;
      readOnly = true;
      internal = true;
      description = "Checked execution observer inputs retained by native activation.";
    };
    compositionRequests = mkOption {
      type = moduleTypes.attrsOf requestBaseType;
      default = {};
      apply = builtins.mapAttrs (_: normalizeRequest);
      readOnly = true;
      internal = true;
      description = "Exact provider child requests derived inside the module fixed point.";
    };
    compositionRequirements = mkOption {
      type = moduleTypes.attrsOf compositionRequirementType;
      default = {};
      readOnly = true;
      internal = true;
      description = "Exact nested implementation requirements derived for provider child requests.";
    };
    compositionPendingRequests = mkOption {
      type = moduleTypes.attrsOf compositionPendingRequestType;
      default = {};
      readOnly = true;
      internal = true;
      description = "Typed child requests retained for the next selected binding-resolution pass.";
    };
    compositionPendingRequirements = mkOption {
      type = moduleTypes.attrsOf compositionPendingRequirementType;
      default = {};
      readOnly = true;
      internal = true;
      description = "Declared conditional requirements retained by exact provider selection group.";
    };
    desiredResources = mkOption {
      type = abilityMapType "desiredResources" desiredResourceBaseType;
      default = {};
      apply = resources: let
        rejected =
          builtins.filter
          (name: !desiredResourceAccepted resources.${name})
          (builtins.attrNames resources);
      in
        if rejected == []
        then resources
        else throw "Desired ability resources do not match their controller contracts: ${builtins.concatStringsSep ", " rejected}.";
      description = "Provider-owned desired resources derived during module evaluation.";
    };
    resolvedResources = mkOption {
      type = moduleTypes.attrsOf resolvedResourceType;
      default = resolvedResourceProjection;
      internal = true;
      readOnly = true;
      description = "Checked desired and published resources with exact identities and semantic revisions.";
    };
  };

  config._module.args.abilityIdentityKeyFor = identityKeyFor;

  config.aos.abilities.instanceIdentities = projectedInstanceIdentities;
}
