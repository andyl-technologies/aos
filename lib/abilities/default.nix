##! lib/abilities/default.nix - Ability declarations and pure composition.
##!
##! The library creates typed authoring values, validates concrete requests,
##! and expands selected providers without performing effects. Authentication,
##! provider selection, and runtime admission remain native responsibilities.
{
  types,
  mkOption,
  evalModules,
}: let
  moduleOptionTypes = types;
  schemas = import ./schema.nix;
  abilityTypes = import ./types.nix {
    inherit mkOption schemas;
    moduleTypes = moduleOptionTypes;
  };
  effects = import ./effects;
  resourceControllerTransition = import ./resource-controller-transition.nix;
  diagnostics = import ./diagnostic.nix;
  packageOutputSelectors = import ./package-output-selectors.nix {inherit diagnostics;};
  packageOutputSelectorsFor = limits:
    import ./package-output-selectors.nix {inherit diagnostics limits;};
  packageProjectionFor = {
    lib,
    abilities,
  }:
    import ./package-projection.nix {inherit lib abilities;};
  inherit
    (packageOutputSelectors)
    canonicalizePackageOutputSelectors
    normalizePackageOutputSelectors
    ;

  fail = message:
    diagnostics.throw "value-type-mismatch" "abilities: ${message}";
  failLimit = message:
    diagnostics.throw "limit-exceeded" "abilities: ${message}";
  failMissingReference = message:
    diagnostics.throw "missing-reference" "abilities: ${message}";
  failResultPhase = message:
    diagnostics.throw "result-phase-mismatch" "abilities: ${message}";
  failMethodContract = message:
    diagnostics.throw "method-contract-mismatch" "abilities: ${message}";

  requireAttrs = context: allowed: value: let
    unexpected =
      if builtins.isAttrs value
      then builtins.filter (name: !(builtins.elem name allowed)) (builtins.attrNames value)
      else [];
  in
    if !builtins.isAttrs value
    then fail "${context} must be an attribute set"
    else if unexpected != []
    then fail "${context} has unsupported fields: ${builtins.concatStringsSep ", " unexpected}"
    else value;

  isLocalKey = abilityTypes.localKey.check;

  isAsciiString = value:
    builtins.isString value
    && builtins.match "[[:cntrl:][:print:]]*" value != null;

  inherit (abilityTypes.limits) maxSafeInteger maxStringLength maxCollectionItems maxDocumentBytes;
  positiveU32Type = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxU32;
  };

  requireLocalKey = context: value:
    if isLocalKey value
    then value
    else fail "${context} must match [A-Za-z0-9._-]+ and contain at most 128 bytes";

  requireQualifiedName = context: value:
    if abilityTypes.qualifiedName.check value
    then value
    else fail "${context} must be a namespace-qualified name";

  requireDeclarationKey = context: value:
    if abilityTypes.declarationKey.check value
    then value
    else fail "${context} must be a qualified declaration key";

  requireDigest = context: value:
    if abilityTypes.digest.check value
    then value
    else fail "${context} must be a sha256 digest";

  descriptorFor = domain: document: "sha256:${builtins.hashString "sha256" (builtins.toJSON {inherit domain document;})}";

  guaranteeIdentity = declaration: {
    inherit (declaration) name version;
    descriptor = descriptorFor "aos.ability.execution-guarantee/v1" {
      inherit (declaration) name version semantics;
    };
  };

  normalizeSemanticValue = value:
    if
      builtins.isAttrs value
      && builtins.attrNames value == ["_type" "closure" "content" "nar_hash" "store_path"]
      && value._type == "aos-artifact-reference"
    then {
      inherit (value) _type closure content nar_hash;
    }
    else if builtins.isAttrs value
    then builtins.mapAttrs (_: normalizeSemanticValue) value
    else if builtins.isList value
    then builtins.map normalizeSemanticValue value
    else value;

  resourceRevision = material:
    descriptorFor "aos.ability.resource-revision/v1" (normalizeSemanticValue material);

  semanticInterfaceDocument = document:
    document
    // {
      interface =
        (builtins.removeAttrs document.interface ["description"])
        // {
          outputs =
            builtins.mapAttrs (_: output: builtins.removeAttrs output ["description"])
            document.interface.outputs;
          methods = builtins.mapAttrs (_: method:
            (builtins.removeAttrs method ["description"])
            // {
              outputs =
                builtins.mapAttrs (_: output: builtins.removeAttrs output ["description"])
                method.outputs;
            })
          document.interface.methods;
        };
    };

  interfaceIdentity = document: {
    inherit (document.interface) name abi;
    descriptor = descriptorFor "aos.ability.interface/v1" (semanticInterfaceDocument document);
  };

  declareInterface = {
    name,
    abi,
    description,
    requestType,
    configurationType ? null,
    outputs ? {},
    methods ? {},
    lifecycle,
    aggregation,
    guarantees ? [],
    requiredFeatures ? [],
  }: {
    inherit name abi description requestType configurationType outputs methods lifecycle aggregation guarantees requiredFeatures;
  };

  makeInterfaceDocument = requiredFeatures: export: {
    schema = "aos.ability.interface/v1";
    required_features = uniqueSortedStrings "required features" requiredFeatures;
    interface = normalizeExport export;
  };

  interfaceDocumentFromDeclaration = declaration: let
    document = makeInterfaceDocument declaration.requiredFeatures (define {
      interface = declaration.name;
      inherit (declaration) abi lifecycle guarantees;
      inherit (declaration) outputs methods;
      requestSchema = declaration.requestType;
      configurationSchema = declaration.configurationType;
      aggregation = declaration.aggregation;
      requires = {};
      composeEntry = "compose";
      transitionEntry = "transition";
      ownsResourceKinds = [];
      compose = _: {};
      transition = _: {};
    });
  in
    document
    // {interface = document.interface // {inherit (declaration) description;};};

  interfaceDeclarationFromDocument = {
    document,
    documentation,
  }: let
    interface = document.interface;
    outputFromDocument = description: output: {
      inherit description;
      schema = abilityTypes.fromSchema output.schema;
      inherit (output) phase visibility lifetime;
    };
    outcomeFromDocument = outcome: {
      completionEvidence = abilityTypes.fromSchema outcome.completion_evidence;
      observationEvidence = abilityTypes.fromSchema outcome.observation_evidence;
      supportsRejectedBeforeEffect = outcome.supports_rejected_before_effect;
      inherit (outcome) indeterminate;
    };
    methodFromDocument = name: method: {
      description = documentation.methods.${name}.description;
      semantics = {
        requiredTargetAccess = method.semantics.required_target_access;
        stopsProvider = method.semantics.stops_provider;
      };
      parameters = abilityTypes.fromSchema method.parameters;
      targetResource = method.target_resource;
      outputs = builtins.mapAttrs (outputName: output:
        outputFromDocument documentation.methods.${name}.outputs.${outputName} output)
      method.outputs;
      permittedOperations = method.permitted_operations;
      inherit (method) guarantees;
      outcome = outcomeFromDocument method.outcome;
    };
  in
    declareInterface {
      description = documentation.description;
      inherit (interface) name abi lifecycle guarantees;
      requestType = abilityTypes.fromSchema interface.request;
      configurationType =
        if interface ? configuration
        then abilityTypes.fromSchema interface.configuration
        else null;
      outputs = builtins.mapAttrs (name: output: outputFromDocument documentation.outputs.${name} output) interface.outputs;
      methods = builtins.mapAttrs methodFromDocument interface.methods;
      aggregation = {
        inherit (interface.aggregation) scope;
        key = interface.aggregation.key;
        rejectSlotCollisions = interface.aggregation.reject_slot_collisions;
        mergeContract = interface.aggregation.merge_contract;
        controllerGroup = interface.aggregation.controller_group;
      };
      requiredFeatures = document.required_features;
    };

  requireU32Positive = context: value:
    if positiveU32Type.check value
    then value
    else fail "${context} must be a positive 32-bit integer";

  requireChoice = context: choices: value:
    if builtins.elem value choices
    then value
    else fail "${context} is unsupported";

  requireMarker = context: marker: value:
    if builtins.isAttrs value && (value._type or null) == marker
    then value
    else fail "${context} must be constructed by lib.abilities";

  hasAdjacentDuplicate = values:
    (builtins.foldl' (
        state: value: {
          previous = value;
          hasPrevious = true;
          duplicate = state.duplicate || (state.hasPrevious && state.previous == value);
        }
      ) {
        previous = null;
        hasPrevious = false;
        duplicate = false;
      }
      values)
    .duplicate;

  uniqueSortedStrings = context: values: let
    sorted =
      if builtins.isList values && builtins.all builtins.isString values
      then builtins.sort builtins.lessThan values
      else fail "${context} must be a list of strings";
  in
    if hasAdjacentDuplicate sorted
    then fail "${context} contains a duplicate value"
    else sorted;

  qualifiedSortedStrings = context: values:
    builtins.map (requireQualifiedName context) (uniqueSortedStrings context values);

  localSortedStrings = context: values:
    builtins.map (requireLocalKey context) (uniqueSortedStrings context values);

  interfaceKey = args: let
    checked = requireAttrs "interface key" ["name" "abi" "descriptor"] args;
  in {
    name = requireQualifiedName "interface name" checked.name;
    abi = requireU32Positive "interface ABI" checked.abi;
    descriptor = requireDigest "interface descriptor" checked.descriptor;
  };

  guaranteeKey = context: value: let
    checked = requireAttrs context ["name" "version" "descriptor"] value;
  in {
    name = requireQualifiedName "${context} name" checked.name;
    version = requireU32Positive "${context} version" checked.version;
    descriptor = requireDigest "${context} descriptor" checked.descriptor;
  };

  guaranteeLessThan = left: right:
    if left.name != right.name
    then left.name < right.name
    else if left.version != right.version
    then left.version < right.version
    else left.descriptor < right.descriptor;

  canonicalGuarantees = context: values: let
    project = value: let
      checked =
        requireAttrs context (
          if value ? semantics
          then ["description" "name" "semantics" "version"]
          else ["descriptor" "name" "version"]
        )
        value;
    in
      if value ? semantics
      then guaranteeIdentity checked
      else guaranteeKey context checked;
    checked =
      if builtins.isList values
      then builtins.map project values
      else fail "${context} must be a list";
    sorted = builtins.sort guaranteeLessThan checked;
  in
    if hasAdjacentDuplicate sorted
    then fail "${context} contains a duplicate guarantee"
    else sorted;

  boundedAdd = limit: left: right:
    if left > limit || right > limit || left > limit - right
    then limit + 1
    else left + right;

  canonicalValueStats = context: depth: value:
    if depth > 64
    then failLimit "${context} exceeds 64 structural levels"
    else if value == null || builtins.isBool value
    then {
      inherit value;
      items = 0;
      bytes = builtins.stringLength (builtins.toJSON value);
    }
    else if builtins.isInt value && value >= -maxSafeInteger && value <= maxSafeInteger
    then {
      inherit value;
      items = 0;
      bytes = builtins.stringLength (builtins.toJSON value);
    }
    else if builtins.isString value && builtins.stringLength value <= maxStringLength
    then {
      inherit value;
      items = 0;
      bytes = builtins.stringLength (builtins.toJSON value);
    }
    else if builtins.isList value
    then let
      length = builtins.length value;
      initial = {
        items = length;
        bytes =
          if length == 0
          then 2
          else length + 1;
      };
      stats =
        builtins.foldl' (
          state: childValue:
            if state.items > maxCollectionItems || state.bytes > maxDocumentBytes
            then state
            else let
              child = canonicalValueStats context (depth + 1) childValue;
            in {
              items = boundedAdd maxCollectionItems state.items child.items;
              bytes = boundedAdd maxDocumentBytes state.bytes child.bytes;
            }
        )
        initial
        value;
    in
      if stats.items <= maxCollectionItems
      then {
        inherit value;
        inherit (stats) items bytes;
      }
      else failLimit "${context} exceeds the collection item limit"
    else if builtins.isAttrs value
    then let
      names = builtins.attrNames value;
      validNames =
        builtins.all (
          name: isAsciiString name && builtins.stringLength name <= maxStringLength
        )
        names;
      length = builtins.length names;
      initial = {
        items = length;
        bytes =
          if length == 0
          then 2
          else length + 1;
      };
      stats =
        builtins.foldl' (
          state: name:
            if state.items > maxCollectionItems || state.bytes > maxDocumentBytes
            then state
            else let
              child = canonicalValueStats context (depth + 1) value.${name};
              keyBytes = builtins.stringLength (builtins.toJSON name) + 1;
            in {
              items = boundedAdd maxCollectionItems state.items child.items;
              bytes = boundedAdd maxDocumentBytes state.bytes (keyBytes + child.bytes);
            }
        )
        initial
        names;
    in
      if !validNames
      then fail "${context} contains a non-canonical object member name"
      else if stats.items > maxCollectionItems
      then failLimit "${context} exceeds the collection item limit"
      else {
        inherit value;
        inherit (stats) items bytes;
      }
    else fail "${context} is outside the canonical ability value domain";

  normalizeRequirementFallback = alias: value: let
    checked = requireAttrs "requirement '${alias}' fallback" ["outputs"] value;
    outputs =
      if builtins.isAttrs checked.outputs
      then checked.outputs
      else fail "requirement '${alias}' fallback outputs must be an attribute set";
    outputNames = builtins.attrNames outputs;
    checkedNames = builtins.map (requireLocalKey "requirement '${alias}' fallback output") outputNames;
    values =
      builtins.mapAttrs (
        output: canonicalValueStats "requirement '${alias}' fallback output '${output}'" 6
      )
      outputs;
    initialStats = {
      items = builtins.length checkedNames;
      bytes =
        if checkedNames == []
        then 14
        else builtins.length checkedNames + 13;
    };
    stats =
      builtins.foldl' (
        state: output:
          if state.items > maxCollectionItems || state.bytes > maxDocumentBytes
          then state
          else let
            child = values.${output};
            keyBytes = builtins.stringLength (builtins.toJSON output) + 1;
          in {
            items = boundedAdd maxCollectionItems state.items child.items;
            bytes = boundedAdd maxDocumentBytes state.bytes (keyBytes + child.bytes);
          }
      )
      initialStats
      checkedNames;
    normalized = {outputs = builtins.mapAttrs (_: child: child.value) values;};
  in
    if stats.items > maxCollectionItems
    then failLimit "requirement '${alias}' fallback exceeds the collection item limit"
    else if stats.bytes > maxDocumentBytes
    then failLimit "requirement '${alias}' fallback exceeds the encoded byte limit"
    else normalized;

  normalizeEnvironmentId = value: let
    checked = requireMarker "environment identity" "aos-environment-id" value;
  in
    builtins.removeAttrs checked ["_type"];

  normalizeInstanceId = value: let
    checked = requireMarker "instance identity" "aos-instance-id" value;
  in {
    environment = normalizeEnvironmentId checked.environment;
    inherit (checked) key;
  };

  normalizeRequestId = value: let
    checked = requireMarker "request identity" "aos-request-id" value;
  in {
    consumer = normalizeInstanceId checked.consumer;
    inherit (checked) scope key;
  };

  normalizeBindingReference = value: let
    checked = requireMarker "binding reference" "aos-ability-binding-reference" value;
  in
    builtins.removeAttrs checked ["_type"];

  normalizeArtifactReference = value: let
    checked = requireMarker "artifact reference" "aos-artifact-reference" value;
  in
    builtins.removeAttrs checked ["_type"];

  sameInterface = left: right:
    left.name
    == right.name
    && left.abi == right.abi
    && (
      !(right ? descriptor)
      || right.descriptor == null
      || left.descriptor == right.descriptor
    );

  interfaceSelectorMatches = selector: interface: sameInterface interface selector;

  interfaceSelector = args: let
    checked = requireAttrs "interface selector" ["name" "abi"] args;
  in {
    interface = requireQualifiedName "interface selector name" checked.name;
    abi = requireU32Positive "interface selector ABI" checked.abi;
    descriptor = null;
  };

  normalizeRequirement = alias: value: let
    checked =
      requireAttrs "requirement '${alias}'" [
        "description"
        "interface"
        "abi"
        "descriptor"
        "methods"
        "guarantees"
        "strength"
        "fallback"
      ]
      value;
    strength = requireChoice "requirement '${alias}' strength" ["required" "advisory"] checked.strength;
    fallback =
      if (checked.fallback or null) == null
      then null
      else normalizeRequirementFallback alias checked.fallback;
  in
    if (strength == "advisory") != (fallback != null)
    then fail "requirement '${alias}' must be advisory exactly when it declares fallback outputs"
    else {
      alias = requireLocalKey "requirement alias" alias;
      inherit (checked) description;
      accepted_interfaces = [
        ({
            name = checked.interface;
            inherit (checked) abi;
          }
          // (
            if (checked.descriptor or null) == null
            then {}
            else {
              descriptor = requireDigest "requirement '${alias}' interface descriptor" checked.descriptor;
            }
          ))
      ];
      methods = uniqueSortedStrings "requirement '${alias}' methods" checked.methods;
      guarantees = canonicalGuarantees "requirement '${alias}' guarantees" (checked.guarantees or []);
      inherit strength fallback;
    };

  normalizeAggregation = value: let
    checked = requireAttrs "aggregation" ["scope" "key" "rejectSlotCollisions" "mergeContract" "controllerGroup"] value;
  in {
    scope =
      if checked.scope == "provider-instance"
      then checked.scope
      else fail "aggregation scope must be 'provider-instance'";
    key = requireLocalKey "aggregation key" checked.key;
    reject_slot_collisions =
      if builtins.isBool checked.rejectSlotCollisions
      then checked.rejectSlotCollisions
      else fail "aggregation rejectSlotCollisions must be a Boolean";
    merge_contract =
      if (checked.mergeContract or null) == null
      then null
      else requireDigest "aggregation mergeContract" checked.mergeContract;
    controller_group = requireLocalKey "aggregation controllerGroup" checked.controllerGroup;
  };

  normalizeOutput = context: value: let
    checked = requireAttrs context ["description" "schema" "phase" "visibility" "lifetime"] value;
  in {
    inherit (checked) description;
    schema = schemaFromType "${context} type" checked.schema;
    phase =
      requireChoice
      "${context} phase"
      ["evaluation" "artifact" "planning" "admission" "runtime" "observation"]
      checked.phase;
    visibility =
      requireChoice "${context} visibility" ["public" "protected" "private"] checked.visibility;
    lifetime =
      requireChoice
      "${context} lifetime"
      ["attempt" "transaction" "instance" "persistent"]
      checked.lifetime;
  };

  normalizeOutcome = context: value: let
    checked = requireAttrs context ["completionEvidence" "observationEvidence" "supportsRejectedBeforeEffect" "indeterminate"] value;
  in {
    completion_evidence = schemaFromType "${context} completionEvidence type" checked.completionEvidence;
    observation_evidence = schemaFromType "${context} observationEvidence type" checked.observationEvidence;
    supports_rejected_before_effect =
      if builtins.isBool checked.supportsRejectedBeforeEffect
      then checked.supportsRejectedBeforeEffect
      else fail "${context} supportsRejectedBeforeEffect must be a Boolean";
    indeterminate =
      requireChoice
      "${context} indeterminate semantics"
      ["reconcile" "intervention-required"]
      checked.indeterminate;
  };

  normalizeLifecycle = value: let
    checked =
      requireAttrs "lifecycle" [
        "persistentDeleteMethod"
      ]
      value;
  in {
    persistent_delete_method =
      if (checked.persistentDeleteMethod or null) == null
      then null
      else requireLocalKey "persistent delete method" checked.persistentDeleteMethod;
  };

  normalizeMethod = name: value: let
    checked =
      requireAttrs "method '${name}'" [
        "description"
        "semantics"
        "parameters"
        "targetResource"
        "outputs"
        "permittedOperations"
        "guarantees"
        "outcome"
      ]
      value;
    semantics = requireAttrs "method '${name}' semantics" ["requiredTargetAccess" "stopsProvider"] checked.semantics;
  in {
    inherit (checked) description;
    semantics = {
      required_target_access =
        requireChoice "method '${name}' required target access"
        ["read" "shared-write" "exclusive-write"]
        semantics.requiredTargetAccess;
      stops_provider =
        if !builtins.isBool semantics.stopsProvider
        then fail "method '${name}' stopsProvider must be a Boolean"
        else if semantics.stopsProvider && semantics.requiredTargetAccess != "exclusive-write"
        then fail "method '${name}' that stops a provider requires exclusive-write target access"
        else semantics.stopsProvider;
    };
    parameters = schemaFromType "method '${name}' parameter type" checked.parameters;
    target_resource = requireQualifiedName "method '${name}' targetResource" checked.targetResource;
    outputs =
      builtins.mapAttrs (
        output: normalizeOutput "method '${name}' output '${requireLocalKey "output name" output}'"
      )
      checked.outputs;
    permitted_operations = uniqueSortedStrings "method '${name}' permittedOperations" checked.permittedOperations;
    guarantees = canonicalGuarantees "method '${name}' guarantees" (checked.guarantees or []);
    outcome = normalizeOutcome "method '${name}' outcome" checked.outcome;
  };

  normalizeOwnedMethod = _: normalizeMethod;

  configurationSchemaIsLiteral = schema:
    if
      builtins.elem schema.kind [
        "artifact-reference"
        "resource-reference"
        "provider-assignment"
        "operation-result-reference"
      ]
    then false
    else if schema.kind == "list"
    then configurationSchemaIsLiteral schema.element
    else if schema.kind == "map" || schema.kind == "optional"
    then configurationSchemaIsLiteral schema.value
    else if builtins.elem schema.kind ["record" "document-record"]
    then builtins.all configurationSchemaIsLiteral (builtins.attrValues schema.fields)
    else if schema.kind == "tagged-union"
    then builtins.all configurationSchemaIsLiteral (builtins.attrValues schema.variants)
    else if schema.kind == "disjoint-union"
    then builtins.all configurationSchemaIsLiteral schema.variants
    else true;

  schemaFromType = context: value:
    abilityTypes.schemaOf context value;

  normalizeConfigurationSchema = value: let
    schema = schemaFromType "export configuration type" value;
  in
    if configurationSchemaIsLiteral schema
    then schema
    else fail "export configurationSchema must contain evaluation literals only";

  define = value: let
    checked =
      requireAttrs "export" [
        "interface"
        "abi"
        "requestSchema"
        "configurationSchema"
        "outputs"
        "methods"
        "lifecycle"
        "guarantees"
        "aggregation"
        "requires"
        "composeEntry"
        "transitionEntry"
        "ownsResourceKinds"
        "desiredType"
        "stateFormat"
        "compose"
        "transition"
        "handler"
        "provide"
      ]
      value;
    handler = checked.handler or null;
    compose = checked.compose or null;
    transition = checked.transition or null;
    provide = checked.provide or null;
    methods = builtins.mapAttrs (normalizeOwnedMethod checked.interface) (checked.methods or {});
    lifecycle = normalizeLifecycle checked.lifecycle;
    stoppingMethods =
      builtins.filter
      (method: method.semantics.stops_provider)
      (builtins.attrValues methods);
    stoppingTargets = builtins.map (method: method.target_resource) stoppingMethods;
    retainedTargets =
      builtins.concatMap
      (method:
        if
          builtins.any
          (output:
            output.schema.kind
            == "resource-reference"
            && builtins.elem output.phase ["runtime" "observation"]
            && output.visibility == "protected"
            && output.lifetime == "instance")
          (builtins.attrValues method.outputs)
        then [method.target_resource]
        else [])
      (builtins.attrValues methods);
    uncoveredRetainedTargets =
      builtins.filter
      (target: !(builtins.elem target stoppingTargets))
      retainedTargets;
    persistentDeleteMethod =
      if lifecycle.persistent_delete_method == null
      then null
      else methods.${lifecycle.persistent_delete_method} or null;
  in
    if (handler == null) == (compose == null)
    then fail "export must declare exactly one of compose or handler"
    else if compose != null && !builtins.isFunction compose
    then fail "export compose must be a function"
    else if compose != null && !builtins.isFunction transition
    then fail "composite export transition must be a function"
    else if handler != null && transition != null
    then fail "terminal export cannot declare a transition constructor"
    else if provide != null && !builtins.isFunction provide
    then fail "terminal provide must be a function"
    else if compose != null && provide != null
    then fail "composite export cannot declare terminal provide semantics"
    else if handler != null && checked.outputs != {} && provide == null
    then fail "terminal export with desired outputs must declare pure provide semantics"
    else if handler != null && !isLocalKey handler
    then fail "export handler must be a local key"
    else if handler != null && (checked.stateFormat or null) != null
    then fail "terminal export cannot declare a provider state format"
    else if (checked.stateFormat or null) != null && (checked.ownsResourceKinds or []) == []
    then fail "provider state format requires at least one owned resource kind"
    else if uncoveredRetainedTargets != []
    then
      fail
      "interface '${checked.interface}' emits an instance-lifetime resource without a provider-stopping method for target '${builtins.head uncoveredRetainedTargets}'"
    else if lifecycle.persistent_delete_method != null && persistentDeleteMethod == null
    then fail "interface '${checked.interface}' names an absent persistent delete method"
    else if persistentDeleteMethod != null && !persistentDeleteMethod.semantics.stops_provider
    then fail "interface '${checked.interface}' persistent delete method must stop the provider"
    else {
      _type = "aos-ability-export";
      interface = {
        name = checked.interface;
        abi = requireU32Positive "interface ABI" checked.abi;
      };
      request_schema = schemaFromType "export request type" checked.requestSchema;
      configuration_schema =
        if (checked.configurationSchema or null) == null
        then null
        else normalizeConfigurationSchema checked.configurationSchema;
      outputs =
        builtins.mapAttrs (
          name: normalizeOutput "interface output '${requireLocalKey "output name" name}'"
        )
        checked.outputs;
      inherit methods lifecycle;
      guarantees = canonicalGuarantees "export guarantees" (checked.guarantees or []);
      aggregation = normalizeAggregation checked.aggregation;
      requirements = builtins.mapAttrs normalizeRequirement (checked.requires or {});
      compose_entry =
        if compose == null
        then null
        else requireLocalKey "composeEntry" checked.composeEntry;
      transition_entry =
        if transition == null
        then null
        else requireLocalKey "transitionEntry" checked.transitionEntry;
      owns_resource_kinds =
        builtins.map
        (requireQualifiedName "owned resource kind")
        (uniqueSortedStrings "owned resource kinds" (checked.ownsResourceKinds or []));
      desired_schema =
        if (checked.desiredType or null) == null
        then null
        else schemas.validateSchema "provider desiredType" checked.desiredType;
      state_format =
        if (checked.stateFormat or null) == null
        then null
        else requireDigest "provider state-format descriptor" checked.stateFormat;
      inherit compose transition handler provide;
      _interface_declaration = {
        description = "Ability interface ${checked.interface}.";
        name = checked.interface;
        abi = checked.abi;
        requestType = checked.requestSchema;
        configurationType = checked.configurationSchema or null;
        outputs = builtins.mapAttrs (name: output:
          output // {description = "Output ${name} from ${checked.interface}.";})
        checked.outputs;
        methods = builtins.mapAttrs (name: method:
          method
          // {
            description = "Method ${name} on ${checked.interface}.";
            outputs = builtins.mapAttrs (outputName: output:
              output // {description = "Output ${outputName} from ${checked.interface}.${name}.";})
            method.outputs;
          })
        (checked.methods or {});
        inherit (checked) lifecycle aggregation;
        guarantees = checked.guarantees or [];
      };
    };

  normalizeExport = value: let
    export = requireMarker "export" "aos-ability-export" value;
  in
    {
      inherit (export._interface_declaration) description;
      inherit (export.interface) name abi;
      request = export.request_schema;
      inherit (export) outputs methods lifecycle guarantees aggregation;
    }
    // (
      if export.configuration_schema == null
      then {}
      else {configuration = export.configuration_schema;}
    );

  normalizeImplementation = artifact: value: let
    export = requireMarker "export" "aos-ability-export" value;
  in
    {
      interface =
        if export.interface ? descriptor
        then export.interface
        else fail "provider implementation requires a validator-derived interface descriptor pin";
      artifact = normalizeArtifactReference artifact;
      requirements =
        builtins.map
        (alias: export.requirements.${alias})
        (builtins.attrNames export.requirements);
      implementation =
        if export.handler != null
        then {
          kind = "terminal-handler";
          handler = export.handler;
        }
        else {
          kind = "pure-composition";
          compose_entry = export.compose_entry;
          transition_entry = export.transition_entry;
        };
      owns_resource_kinds = export.owns_resource_kinds;
    }
    // (
      if export.desired_schema == null
      then {}
      else {desired_schema = export.desired_schema;}
    )
    // (
      if export.state_format == null
      then {}
      else {
        state_format = {
          descriptor = export.state_format;
          artifact = normalizeArtifactReference artifact;
        };
      }
    );

  normalizeExportDeclaration = name: implementation: value: let
    export = requireMarker "export" "aos-ability-export" value;
  in {
    name = requireLocalKey "package export name" name;
    interface =
      if export.interface ? descriptor
      then export.interface
      else fail "package export requires a validator-derived interface descriptor pin";
    implementation = requireDigest "provider implementation descriptor" implementation;
  };

  normalizeContribution = export: value: let
    contribution = requireMarker "contribution" "aos-ability-contribution" value;
  in {
    request = normalizeRequestId contribution.request;
    inherit (contribution) slot grant;
    value = checkCompositionValue export.request_schema contribution.value;
  };

  stageRank = stage:
    {
      build = 0;
      initrd = 1;
      host = 2;
      system-container = 3;
      user = 4;
      application-container = 5;
    }
    .${
      stage
    };

  scopeLessThan = left: right:
    if left == []
    then right != []
    else if right == []
    then false
    else if builtins.head left != builtins.head right
    then builtins.head left < builtins.head right
    else scopeLessThan (builtins.tail left) (builtins.tail right);

  requestIdLessThan = left: right: let
    leftEnvironment = left.consumer.environment;
    rightEnvironment = right.consumer.environment;
  in
    if leftEnvironment.authority != rightEnvironment.authority
    then leftEnvironment.authority < rightEnvironment.authority
    else if leftEnvironment.key != rightEnvironment.key
    then leftEnvironment.key < rightEnvironment.key
    else if leftEnvironment.stage != rightEnvironment.stage
    then stageRank leftEnvironment.stage < stageRank rightEnvironment.stage
    else if left.consumer.key != right.consumer.key
    then left.consumer.key < right.consumer.key
    else if left.scope != right.scope
    then scopeLessThan left.scope right.scope
    else left.key < right.key;

  contributionLessThan = left: right:
    if left.slot != right.slot
    then left.slot < right.slot
    else requestIdLessThan left.request right.request;

  canonicalContributions = export: values: let
    checked =
      if builtins.isList values && builtins.length values <= maxCollectionItems
      then builtins.map (normalizeContribution export) values
      else fail "contributions must fit the bounded profile";
    sorted = builtins.sort contributionLessThan checked;
    duplicateSlot =
      (
        builtins.foldl' (
          state: entry:
            if state.duplicate != null
            then state
            else {
              previous = entry.slot;
              duplicate =
                if state.previous == entry.slot
                then entry.slot
                else null;
            }
        ) {
          previous = null;
          duplicate = null;
        }
        sorted
      )
      .duplicate;
  in
    if export.aggregation.reject_slot_collisions && duplicateSlot != null
    then fail "exclusive contribution slot collision: ${duplicateSlot}"
    else sorted;

  validateBindings = export: bindings: let
    requirementAliases = builtins.attrNames export.requirements;
    bindingAliases = builtins.attrNames bindings;
    unexpected = builtins.filter (name: !(builtins.elem name requirementAliases)) bindingAliases;
    checked =
      builtins.mapAttrs (
        alias: value: let
          binding = requireMarker "binding '${alias}'" "aos-ability-binding-reference" value;
        in
          if binding.requirement != alias
          then fail "binding '${alias}' names requirement '${binding.requirement}'"
          else if
            !builtins.any
            (candidate: sameInterface binding.interface candidate)
            export.requirements.${alias}.accepted_interfaces
          then fail "binding '${alias}' does not match its declared interface"
          else binding
      )
      bindings;
  in
    if unexpected != []
    then fail "undeclared requirement bindings: ${builtins.concatStringsSep ", " unexpected}"
    else checked;

  containsRequestOutput = depth: value:
    if depth > 64
    then failLimit "composition value exceeds 64 structural levels"
    else if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then true
    else if builtins.isAttrs value && !((value.type or null) == "derivation")
    then builtins.any (containsRequestOutput (depth + 1)) (builtins.attrValues value)
    else if builtins.isList value
    then builtins.any (containsRequestOutput (depth + 1)) value
    else false;

  checkCompositionValue = schemaValue: value: let
    schema = schemas.validateSchema "composition value schema" schemaValue;
    resultMarker = builtins.isAttrs value && (value._type or null) == "aos-request-output-reference";
    pathMarker = builtins.isAttrs value && (value._type or null) == "aos-runtime-path";
    invalid = expected: fail "composition value must be ${expected}";
    valueKind = candidate:
      if builtins.isBool candidate
      then "boolean"
      else if builtins.isInt candidate || builtins.isFloat candidate
      then "number"
      else if builtins.isString candidate
      then "string"
      else if builtins.isList candidate
      then "array"
      else if builtins.isAttrs candidate
      then "object"
      else null;
  in
    if resultMarker
    then value
    else if pathMarker
    then let
      checked = requireAttrs "path-within expression" ["_type" "base" "relative_path"] value;
    in
      if schema.kind != "string" || schema.syntax != "execution-path-v1"
      then invalid "an execution path"
      else if !abilityTypes.relativePath.check checked.relative_path
      then fail "path-within relative path is not normalized"
      else checked // {base = checkCompositionValue schema checked.base;}
    else if !containsRequestOutput 0 value
    then schemas.checkValue schema value
    else if schema.kind == "list"
    then
      if builtins.isList value && builtins.length value <= schema.max_items
      then builtins.map (checkCompositionValue schema.element) value
      else invalid "a bounded list"
    else if schema.kind == "map"
    then let
      entries =
        if builtins.isAttrs value
        then value
        else invalid "a map";
      names = builtins.attrNames entries;
      validKey = name:
        isAsciiString name
        && builtins.stringLength name <= schema.key.max_length
        && (
          schema.key.syntax
          == null
          || (schema.key.syntax == "local-key-v1" && isLocalKey name)
          || (
            schema.key.syntax
            == "qualified-name-v1"
            && abilityTypes.qualifiedName.check name
          )
        );
    in
      if builtins.length names > schema.max_entries || !(builtins.all validKey names)
      then invalid "a map with valid bounded keys"
      else builtins.mapAttrs (_: checkCompositionValue schema.value) entries
    else if builtins.elem schema.kind ["record" "document-record"]
    then let
      record =
        if builtins.isAttrs value
        then value
        else invalid "a record";
      names = builtins.attrNames record;
      fieldNames = builtins.attrNames schema.fields;
      missing =
        builtins.filter (
          name: !(builtins.elem name schema.optional_fields) && !(builtins.hasAttr name record)
        )
        fieldNames;
      unexpected = builtins.filter (name: !(builtins.hasAttr name schema.fields)) names;
    in
      if missing != [] || unexpected != []
      then invalid "a closed record with all required fields"
      else builtins.mapAttrs (name: checkCompositionValue schema.fields.${name}) record
    else if schema.kind == "tagged-union"
    then let
      tag =
        if builtins.isAttrs value
        then value.${schema.tag} or null
        else null;
    in
      if builtins.isString tag && builtins.hasAttr tag schema.variants
      then checkCompositionValue schema.variants.${tag} value
      else invalid "a declared tagged-union variant"
    else if schema.kind == "disjoint-union"
    then let
      kind = valueKind value;
      matching = builtins.filter (variant: schemas.topLevelKind variant == kind) schema.variants;
    in
      if kind != null && builtins.length matching == 1
      then checkCompositionValue (builtins.head matching) value
      else invalid "a declared disjoint-union variant"
    else if schema.kind == "optional"
    then
      if value == null
      then null
      else checkCompositionValue schema.value value
    else invalid "a literal value without a nested symbolic projection";

  compose = args: let
    checkedArgs = requireAttrs "compose arguments" ["export" "contributions" "bindings" "instance" "scope"] args;
    export = requireMarker "export" "aos-ability-export" checkedArgs.export;
    instance = requireMarker "instance context" "aos-instance-context" checkedArgs.instance;
    scope = builtins.map (requireLocalKey "composition scope") (checkedArgs.scope or []);
    contributions = canonicalContributions export checkedArgs.contributions;
    bindings = validateBindings export checkedArgs.bindings;
    requests = builtins.listToAttrs (builtins.map (entry: {
        name = entry.slot;
        value = entry.value;
      })
      contributions);
    authored =
      if export.handler != null
      then
        if export.provide == null
        then {
          requests = {};
          outputs = {};
          resources = [];
          conditionalRequirements = [];
        }
        else
          export.provide {
            inherit requests;
            instance = instance.values // {id = instance.id;};
          }
      else
        export.compose {
          inherit requests bindings;
          instance = instance.values // {id = instance.id;};
        };
    checkedAuthored =
      requireAttrs "composition result" [
        "requests"
        "outputs"
        "resources"
        "conditionalRequirements"
      ]
      authored;
    childRequests =
      builtins.mapAttrs (
        name: child: let
          checked = requireAttrs "child request '${name}'" ["through" "parameters" "lifetime" "slot"] child;
          binding = requireMarker "child request '${name}' binding" "aos-ability-binding-reference" checked.through;
          alias = binding.requirement;
          selected = bindings.${alias} or null;
          requirement = export.requirements.${alias};
          requestIdentity = {
            _type = "aos-request-id";
            consumer = instance.id;
            scope = scope ++ [name];
            key = name;
          };
        in {
          key =
            if
              selected
              != null
              && selected.binding == binding.binding
              && selected.provider_key == binding.provider_key
              && sameInterface selected.interface binding.interface
            then requireLocalKey "child request key" name
            else fail "child request '${name}' does not use its declared binding";
          through = binding;
          request = requestIdentity;
          id = normalizeRequestId requestIdentity;
          inherit (requirement) accepted_interfaces methods guarantees;
          lifetime =
            if builtins.elem (checked.lifetime or "instance") ["attempt" "transaction" "instance" "persistent"]
            then checked.lifetime or "instance"
            else fail "child request '${name}' has unsupported lifetime";
          slot = requireLocalKey "child request '${name}' slot" (checked.slot or "${instance.id.key}.${name}");
          value = checked.parameters;
        }
      )
      checkedAuthored.requests;
    terminalRequests = export.handler != null && checkedAuthored.requests != {};

    outputNames = builtins.attrNames export.outputs;
    missingOutputs = builtins.filter (name: !(builtins.hasAttr name checkedAuthored.outputs)) outputNames;
    unexpectedOutputs = builtins.filter (name: !(builtins.hasAttr name export.outputs)) (builtins.attrNames checkedAuthored.outputs);
    outputs =
      builtins.mapAttrs (
        name: value: checkCompositionValue export.outputs.${name}.schema value
      )
      checkedAuthored.outputs;
    activeRequirements =
      uniqueSortedStrings
      "conditional requirements"
      (checkedAuthored.conditionalRequirements or []);
    unknownActiveRequirements =
      builtins.filter
      (alias: !(builtins.hasAttr alias export.requirements))
      activeRequirements;
    unboundActiveRequirements =
      builtins.filter
      (alias: !(builtins.hasAttr alias bindings))
      activeRequirements;
  in
    {
      provider = normalizeInstanceId instance.id;
      interface = export.interface;
      aggregate = {
        provider = normalizeInstanceId instance.id;
        group = export.aggregation.controller_group;
      };
      inherit scope contributions outputs;
      child_requests = builtins.map (name: childRequests.${name}) (builtins.attrNames childRequests);
      resources = checkedAuthored.resources or [];
      conditional_requirements = activeRequirements;
      terminal_handler = export.handler;
    }
    // (
      if missingOutputs != []
      then fail "composition omits outputs: ${builtins.concatStringsSep ", " missingOutputs}"
      else if unexpectedOutputs != []
      then fail "composition returned undeclared outputs: ${builtins.concatStringsSep ", " unexpectedOutputs}"
      else if unknownActiveRequirements != []
      then fail "composition activated undeclared requirements: ${builtins.concatStringsSep ", " unknownActiveRequirements}"
      else if unboundActiveRequirements != []
      then fail "composition activated unbound requirements: ${builtins.concatStringsSep ", " unboundActiveRequirements}"
      else if terminalRequests
      then fail "terminal provide semantics cannot emit lower requests"
      else {}
    );

  appendPending = providerName: contribution: pending:
    pending
    // {
      ${providerName} = [contribution] ++ (pending.${providerName} or []);
    };

  countPending = pending:
    builtins.foldl'
    (count: contributions: count + builtins.length contributions)
    0
    (builtins.attrValues pending);

  expand = args: let
    checkedArgs = requireAttrs "expansion arguments" ["roots" "providers"] args;
    providers =
      if builtins.isAttrs checkedArgs.providers
      then checkedArgs.providers
      else fail "providers must be an attribute set";
    roots =
      if builtins.isList checkedArgs.roots && builtins.length checkedArgs.roots <= 100000
      then checkedArgs.roots
      else fail "roots must fit the bounded profile";

    validateProvider = providerName: let
      provider =
        if builtins.hasAttr providerName providers
        then providers.${providerName}
        else fail "selected provider '${providerName}' is absent";
      checked = requireAttrs "provider '${providerName}'" ["export" "instance" "bindings" "scope"] provider;
      scope =
        builtins.map
        (requireLocalKey "provider '${providerName}' scope")
        (checked.scope or [providerName]);
    in
      if builtins.length scope > 63
      then fail "provider '${providerName}' scope leaves no room for a child request"
      else checked // {inherit scope;};

    registryValid = let
      state = builtins.foldl' (
        accumulated: providerName: let
          provider = validateProvider providerName;
          export = requireMarker "provider export" "aos-ability-export" provider.export;
          aggregate = builtins.toJSON {
            provider = normalizeInstanceId provider.instance.id;
            group = export.aggregation.controller_group;
          };
        in
          if builtins.hasAttr aggregate accumulated
          then fail "provider aliases '${accumulated.${aggregate}}' and '${providerName}' name the same aggregate"
          else accumulated // {${aggregate} = providerName;}
      ) {} (builtins.attrNames providers);
    in
      builtins.length (builtins.attrNames state) == builtins.length (builtins.attrNames providers);

    rootPending =
      builtins.foldl' (
        pending: root: let
          checked = requireAttrs "expansion root" ["provider" "contributions"] root;
          providerName = requireLocalKey "root provider" checked.provider;
          contributions =
            if builtins.isList checked.contributions
            then checked.contributions
            else fail "root contributions must be a list";
        in
          builtins.foldl'
          (state: contribution: appendPending providerName contribution state)
          (pending // {${providerName} = pending.${providerName} or [];})
          contributions
      ) {}
      roots;

    composeRound = pending:
      builtins.mapAttrs (
        providerName: contributions: let
          provider = validateProvider providerName;
        in
          compose {
            export = provider.export;
            inherit contributions;
            bindings = provider.bindings or {};
            instance = provider.instance;
            inherit (provider) scope;
          }
      )
      pending;

    resolveComposition = nodes: sourceName: schemaValue: value: trail: let
      schema = schemas.validateSchema "composition projection schema" schemaValue;
      resultMarker = builtins.isAttrs value && (value._type or null) == "aos-request-output-reference";
      pathMarker = builtins.isAttrs value && (value._type or null) == "aos-runtime-path";
      sourceNode = nodes.${sourceName};
      valueKind = candidate:
        if builtins.isBool candidate
        then "boolean"
        else if builtins.isInt candidate || builtins.isFloat candidate
        then "number"
        else if builtins.isString candidate
        then "string"
        else if builtins.isList candidate
        then "array"
        else if builtins.isAttrs candidate
        then "object"
        else null;
    in
      if pathMarker
      then let
        checked = checkCompositionValue schema value;
        base = resolveComposition nodes sourceName schema checked.base trail;
      in
        if builtins.isString base
        then let
          separator =
            if base == "/"
            then ""
            else "/";
          joined = "${base}${separator}${checked.relative_path}";
        in
          if abilityTypes.executionPath.check joined
          then joined
          else fail "path-within expression did not resolve to a normalized absolute path"
        else if builtins.isAttrs base && (base._type or null) == "aos-request-output-reference"
        then checked // {inherit base;}
        else fail "path-within base did not resolve to an execution path"
      else if resultMarker
      then let
        matches =
          builtins.filter
          (child: child.key == value.request)
          sourceNode.child_requests;
        child =
          if builtins.length matches == 1
          then builtins.head matches
          else failMissingReference "resultOf names unknown child request '${value.request}' in '${sourceName}'";
        targetName = child.through.provider_key;
        referenceName = "${sourceName}.${value.request}.${value.output}";
      in
        if builtins.elem referenceName trail
        then fail "composition output cycle includes '${referenceName}'"
        else if !(builtins.hasAttr targetName nodes)
        then value
        else let
          targetExport = (validateProvider targetName).export;
        in
          if !(builtins.hasAttr value.output targetExport.outputs)
          then failMissingReference "resultOf references absent output '${targetName}.${value.output}'"
          else if !(builtins.hasAttr value.output nodes.${targetName}.outputs)
          then failMissingReference "provider '${targetName}' omitted output '${value.output}'"
          else let
            descriptor = targetExport.outputs.${value.output};
            targetValue = nodes.${targetName}.outputs.${value.output};
          in
            if !(builtins.elem descriptor.phase ["evaluation" "planning"])
            then failResultPhase "resultOf '${referenceName}' is unavailable during pure composition"
            else if descriptor.schema != schema
            then fail "resultOf '${referenceName}' has a different output schema"
            else resolveComposition nodes targetName schema targetValue (trail ++ [referenceName])
      else let
        checked = checkCompositionValue schema value;
      in
        if !containsRequestOutput 0 checked
        then checked
        else if builtins.isAttrs checked && (checked._type or null) == "aos-runtime-path"
        then checked // {base = resolveComposition nodes sourceName schema checked.base trail;}
        else if schema.kind == "list"
        then let
          resolved = builtins.map (entry: resolveComposition nodes sourceName schema.element entry trail) checked;
        in
          if containsRequestOutput 0 resolved
          then resolved
          else schemas.checkValue schema resolved
        else if schema.kind == "map"
        then builtins.mapAttrs (_: entry: resolveComposition nodes sourceName schema.value entry trail) checked
        else if builtins.elem schema.kind ["record" "document-record"]
        then
          builtins.mapAttrs
          (name: entry: resolveComposition nodes sourceName schema.fields.${name} entry trail)
          checked
        else if schema.kind == "tagged-union"
        then let
          variant = schema.variants.${checked.${schema.tag}};
        in
          builtins.mapAttrs
          (name: entry: resolveComposition nodes sourceName variant.fields.${name} entry trail)
          checked
        else if schema.kind == "disjoint-union"
        then let
          kind = valueKind checked;
          matching = builtins.filter (variant: schemas.topLevelKind variant == kind) schema.variants;
        in
          if builtins.length matching == 1
          then resolveComposition nodes sourceName (builtins.head matching) checked trail
          else fail "composition value has no declared disjoint-union variant"
        else if schema.kind == "optional"
        then
          if checked == null
          then null
          else resolveComposition nodes sourceName schema.value checked trail
        else fail "symbolic composition output occurs under a scalar schema";

    emitNodeRequests = nodes: sourceName: pending: node:
      builtins.foldl' (
        state: child: let
          targetName = child.through.provider_key;
          target = validateProvider targetName;
          targetExport = requireMarker "target export" "aos-ability-export" target.export;
          childValue =
            if sameInterface child.through.interface targetExport.interface
            then resolveComposition nodes sourceName targetExport.request_schema child.value []
            else fail "selected provider '${targetName}' implements a different interface";
          contribution = {
            _type = "aos-ability-contribution";
            inherit (child) request slot;
            grant = child.through.binding;
            value = childValue;
            _source = sourceName;
          };
        in
          appendPending targetName contribution state
      )
      pending
      node.child_requests;

    nextPending = nodes:
      builtins.foldl'
      (pending: sourceName: emitNodeRequests nodes sourceName pending nodes.${sourceName})
      rootPending
      (builtins.attrNames nodes);

    validateNodeGraph = nodes: let
      names = builtins.attrNames nodes;
      targets = name:
        builtins.map
        (child: child.through.provider_key)
        nodes.${name}.child_requests;
      visit = path: resolved: name:
        if builtins.hasAttr name resolved
        then resolved
        else if builtins.elem name path
        then fail "recursive provider cycle: ${builtins.concatStringsSep " -> " (path ++ [name])}"
        else let
          knownTargets =
            builtins.filter
            (target: builtins.hasAttr target nodes)
            (targets name);
          withTargets =
            builtins.foldl'
            (state: target: visit (path ++ [name]) state target)
            resolved
            knownTargets;
        in
          withTargets // {${name} = true;};
      resolved = builtins.foldl' (visit []) {} names;
    in
      builtins.length (builtins.attrNames resolved) == builtins.length names;

    converge = round: pending:
      if round > 64
      then fail "composition did not converge within 64 rounds"
      else if builtins.length (builtins.attrNames pending) > 100000
      then failLimit "composition exceeds 100000 provider aggregates"
      else if countPending pending > maxCollectionItems
      then failLimit "composition exceeds ${builtins.toString maxCollectionItems} contributions"
      else let
        nodes = composeRound pending;
        following = nextPending nodes;
      in
        assert validateNodeGraph nodes;
          if following == pending
          then {inherit round nodes;}
          else converge (round + 1) following;

    result = converge 1 rootPending;
  in
    assert registryValid;
    assert validateNodeGraph result.nodes; {
      _type = "aos-ability-expansion";
      inherit (result) round;
      nodes =
        builtins.map
        (providerName: result.nodes.${providerName} // {registry_key = providerName;})
        (builtins.attrNames result.nodes);
    };

  transition = args: let
    checked =
      requireAttrs "transition arguments" [
        "export"
        "scope"
        "old"
        "desired"
        "changes"
        "resources"
        "bindings"
        "observations"
      ]
      args;
    export = requireMarker "export" "aos-ability-export" checked.export;
  in
    if export.transition == null
    then fail "export does not define a transition constructor"
    else
      effects.normalize checked.scope (export.transition {
        inherit (checked) old desired changes resources bindings observations;
      });
in rec {
  inherit
    schemas
    effects
    resourceControllerTransition
    define
    declareInterface
    normalizeExport
    normalizeExportDeclaration
    normalizeImplementation
    compose
    expand
    transition
    descriptorFor
    guaranteeIdentity
    interfaceIdentity
    interfaceSelector
    interfaceDocumentFromDeclaration
    interfaceDeclarationFromDocument
    interfaceSelectorMatches
    canonicalizePackageOutputSelectors
    normalizePackageOutputSelectors
    packageOutputSelectorsFor
    packageProjectionFor
    resourceRevision
    ;
  types = abilityTypes;
  interfaces = rec {
    serviceManagement = import ./service-management.nix {
      inherit declareInterface descriptorFor interfaceDocumentFromDeclaration interfaceIdentity;
      types = abilityTypes;
    };
    networkPolicy = import ./network-policy.nix {
      inherit declareInterface descriptorFor interfaceDocumentFromDeclaration interfaceIdentity;
      types = abilityTypes;
    };
    bootPreparation = import ./boot-preparation.nix {
      inherit declareInterface interfaceDocumentFromDeclaration interfaceIdentity;
      types = abilityTypes;
    };
    kernelTunables = import ./kernel-tunables.nix {
      inherit declareInterface interfaceDocumentFromDeclaration interfaceIdentity;
      types = abilityTypes;
    };
    blockStorage = import ./block-storage.nix {
      inherit declareInterface interfaceDocumentFromDeclaration interfaceIdentity;
      types = abilityTypes;
    };
    contentAddressedArtifacts = import ./content-addressed-artifacts.nix {
      inherit declareInterface interfaceDocumentFromDeclaration interfaceIdentity;
      types = abilityTypes;
    };
  };
  module = {config, ...}:
    import ./module.nix {
      inherit
        config
        mkOption
        abilityTypes
        schemas
        evalModules
        interfaceDocumentFromDeclaration
        guaranteeIdentity
        interfaceIdentity
        normalizeSemanticValue
        normalizePackageOutputSelectors
        resourceRevision
        ;
      coreGuarantees = interfaces.serviceManagement.guaranteeDeclarations;
      coreInterfaces =
        interfaces.serviceManagement.moduleDeclarations
        // interfaces.networkPolicy.declarations
        // interfaces.bootPreparation.declarations
        // interfaces.kernelTunables.declarations
        // interfaces.blockStorage.declarations
        // interfaces.contentAddressedArtifacts.declarations;
      moduleTypes = moduleOptionTypes;
    };

  normalizeRequirements = values:
    builtins.map
    (alias: normalizeRequirement alias values.${alias})
    (builtins.attrNames values);

  guarantee = value: let
    checked = requireAttrs "guarantee" ["description" "name" "semantics" "version"] value;
  in {
    name = requireQualifiedName "guarantee name" checked.name;
    version = requireU32Positive "guarantee version" checked.version;
    semantics =
      if
        builtins.isString checked.semantics
        && checked.semantics != ""
        && builtins.stringLength checked.semantics <= maxStringLength
        && builtins.match "[^[:cntrl:]]+" checked.semantics != null
      then checked.semantics
      else fail "guarantee semantics must be non-empty, control-free, and within the string limit";
    description =
      if
        builtins.isString checked.description
        && checked.description != ""
        && builtins.stringLength checked.description <= maxStringLength
        && builtins.match "[^[:cntrl:]]+" checked.description != null
      then checked.description
      else fail "guarantee description must be non-empty, control-free, and within the string limit";
  };

  resultOf = request: output: {
    _type = "aos-request-output-reference";
    request = requireLocalKey "result request" request;
    output = requireLocalKey "result output" output;
  };

  pathWithin = args: let
    checked = requireAttrs "path-within expression" ["base" "relativePath"] args;
    isEffectResult = value:
      builtins.isAttrs value
      && builtins.attrNames value == ["_type" "key" "kind" "output" "up"]
      && value._type == "aos-effect-result-reference"
      && builtins.elem value.kind ["operation" "merge"]
      && builtins.isInt value.up
      && value.up >= 0
      && value.up <= 64
      && abilityTypes.localKey.check value.key
      && abilityTypes.localKey.check value.output;
    validBase = value:
      abilityTypes.executionPath.check value
      || (abilityTypes.deferredResult abilityTypes.executionPath).check value
      || isEffectResult value
      || (
        builtins.isAttrs value
        && (value._type or null) == "aos-runtime-path"
        && abilityTypes.relativePath.check (value.relative_path or null)
        && validBase (value.base or null)
      );
    candidate = {
      _type = "aos-runtime-path";
      inherit (checked) base;
      relative_path = checked.relativePath;
    };
  in
    if validBase candidate.base && abilityTypes.relativePath.check candidate.relative_path
    then candidate
    else fail "path-within requires a deferred execution path base and normalized relative path";

  compositionRequirementKey = args: let
    checked = requireAttrs "composition requirement identity" ["implementation" "alias"] args;
  in "composition:requirement-${builtins.hashString "sha256" (builtins.toJSON {
    schema = "aos.ability.composition-requirement-key/v1";
    implementation = requireDeclarationKey "composition implementation" checked.implementation;
    alias = requireLocalKey "composition requirement alias" checked.alias;
  })}";

  compositionRequestKey = args: let
    checked = requireAttrs "composition request identity" ["implementation" "providerInstance" "key"] args;
  in "composition:request-${builtins.hashString "sha256" (builtins.toJSON {
    schema = "aos.ability.composition-request-key/v1";
    implementation = requireDeclarationKey "composition implementation" checked.implementation;
    provider_instance = requireDeclarationKey "composition provider instance" checked.providerInstance;
    key = requireLocalKey "composition request key" checked.key;
  })}";

  packageOutput = args: let
    checked = requireAttrs "package output selector" ["package" "output"] args;
  in {
    _type = "aos-package-output-selector";
    package = requireLocalKey "package output package" (checked.package or "self");
    output = requireLocalKey "package output output" (checked.output or "out");
  };

  configArtifact = args: let
    checked = requireAttrs "configuration artifact selector" ["name"] args;
  in {
    _type = "aos-config-artifact-selector";
    name = requireLocalKey "configuration artifact name" checked.name;
  };

  pinInterface = args: let
    checked = requireAttrs "interface pin" ["export" "descriptor"] args;
    export = requireMarker "interface pin export" "aos-ability-export" checked.export;
  in
    export
    // {
      interface =
        export.interface
        // {
          descriptor = requireDigest "interface pin descriptor" checked.descriptor;
        };
    };

  environmentId = args: let
    checked = requireAttrs "environment identity" ["authority" "key" "stage"] args;
  in {
    _type = "aos-environment-id";
    authority = requireLocalKey "environment authority" checked.authority;
    key = requireLocalKey "environment key" checked.key;
    stage =
      requireChoice "environment stage" [
        "build"
        "initrd"
        "host"
        "system-container"
        "user"
        "application-container"
      ]
      checked.stage;
  };

  instanceId = args: let
    checked = requireAttrs "instance identity" ["environment" "key"] args;
  in {
    _type = "aos-instance-id";
    environment = requireMarker "instance environment" "aos-environment-id" checked.environment;
    key = requireLocalKey "instance key" checked.key;
  };

  requestId = args: let
    checked = requireAttrs "request identity" ["consumer" "scope" "key"] args;
    scope = builtins.map (requireLocalKey "request scope") checked.scope;
  in {
    _type = "aos-request-id";
    consumer = requireMarker "request consumer" "aos-instance-id" checked.consumer;
    scope =
      if builtins.length scope <= 64
      then scope
      else failLimit "request scope exceeds 64 components";
    key = requireLocalKey "request key" checked.key;
  };

  instance = args: let
    checked = requireAttrs "instance context" ["id" "values"] args;
  in {
    _type = "aos-instance-context";
    id = requireMarker "instance id" "aos-instance-id" checked.id;
    values = checked.values;
  };

  request = args: let
    checked = requireAttrs "ability import" ["interface" "abi" "descriptor" "request"] args;
  in {
    _type = "aos-ability-import";
    interface = interfaceKey {
      name = checked.interface;
      inherit (checked) abi descriptor;
    };
    inherit (checked) request;
  };

  bindingReference = args: let
    checked = requireAttrs "binding reference" ["binding" "requirement" "providerKey" "provider" "interface"] args;
  in {
    _type = "aos-ability-binding-reference";
    binding = requireLocalKey "binding key" checked.binding;
    requirement = requireLocalKey "binding requirement" checked.requirement;
    provider_key = requireLocalKey "binding provider key" checked.providerKey;
    provider = normalizeInstanceId checked.provider;
    interface = interfaceKey checked.interface;
  };

  contribution = args: let
    checked = requireAttrs "contribution" ["request" "slot" "grant" "value"] args;
  in {
    _type = "aos-ability-contribution";
    request = requireMarker "contribution request" "aos-request-id" checked.request;
    slot = requireLocalKey "contribution slot" checked.slot;
    grant = requireLocalKey "contribution grant" checked.grant;
    inherit (checked) value;
  };

  resourceReference = args: let
    checked =
      requireAttrs "resource reference" [
        "interface"
        "resource"
        "operations"
        "lifetime"
      ]
      args;
  in {
    _type = "aos-resource-reference";
    interface = interfaceKey checked.interface;
    resource = {
      provider = normalizeInstanceId checked.resource.provider;
      key = requireLocalKey "resource key" checked.resource.key;
    };
    operations = localSortedStrings "resource operations" checked.operations;
    lifetime = requireChoice "resource lifetime" ["attempt" "transaction" "instance" "persistent"] checked.lifetime;
  };

  artifactReference = args: let
    checked = requireAttrs "artifact reference" ["content" "storePath" "narHash" "closure"] args;
  in {
    _type = "aos-artifact-reference";
    content = requireDigest "artifact content" checked.content;
    store_path =
      if builtins.isString checked.storePath
      then checked.storePath
      else fail "artifact storePath must be a string";
    nar_hash = requireDigest "artifact NAR hash" checked.narHash;
    closure = requireDigest "artifact closure" checked.closure;
  };

  interfaceDocument = makeInterfaceDocument;
}
