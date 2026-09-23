##! lib/abilities/default.nix - Typed ability declarations and shared values.
##!
##! The library defines the typed values used by the module fixed point and
##! serializes its declarations into the canonical runtime documents.
{
  types,
  mkOption,
  evalModules,
  interfaceDirectory ? null,
}: let
  moduleOptionTypes = types;
  schemas = import ./schema.nix;
  abilityTypes = import ./types.nix {
    inherit mkOption schemas;
    moduleTypes = moduleOptionTypes;
  };
  resourceControllerTransition = args:
    import ./resource-controller-transition.nix ({inherit transitionFragment;} // args);
  diagnostics = import ./diagnostic.nix;
  packageOutputSelectors = import ./package-output-selectors.nix {inherit diagnostics;};
  packageOutputSelectorsFor = limits:
    import ./package-output-selectors.nix {inherit diagnostics limits;};
  packageProjectionFor = {
    lib,
    abilities,
  }:
    import ./package-projection.nix {inherit lib abilities;};
  sourceStageFixedPoint = abilities:
    import ./source-stage-fixed-point.nix {
      inherit abilities guaranteeIdentity normalizeRequirement;
    };
  packageAbilitiesFromProjection = projection: {
    inherit (projection) guarantees interfaces;
    implementations = builtins.listToAttrs (map (implementation: {
        name = implementation.name;
        value = implementation;
      })
      projection.implementation.providers);
    requirementTemplates = builtins.listToAttrs (map (requirement: {
        name = requirement.alias;
        value = requirement;
      })
      projection.requirements);
  };
  authenticatedPackageOutputs = import ./authenticated-package-outputs.nix {};
  checkedProviderModuleEvaluation = {
    before,
    after,
  }: let
    declarationCollections = [
      "guarantees"
      "interfaces"
      "implementations"
      "requirementTemplates"
      "instances"
      "requests"
    ];
    introducedDeclarations =
      builtins.filter
      (collection:
        builtins.attrNames after.${collection}
        != builtins.attrNames before.${collection})
      declarationCollections;
  in
    if builtins.deepSeq (builtins.attrValues after.bindings) after.bindings != before.bindings
    then throw "selected provider modules introduced bindings outside the explicit source composition"
    else if introducedDeclarations != []
    then throw "selected provider modules changed declaration collections: ${builtins.concatStringsSep ", " introducedDeclarations}"
    else after;
  interfaceRegistry =
    if interfaceDirectory == null
    then {
      module.imports = [];
      readView = {};
    }
    else
      import interfaceDirectory {
        inherit
          declareInterface
          descriptorFor
          interfaceDocumentFromDeclaration
          interfaceIdentity
          ;
        types = abilityTypes;
      };
  inherit
    (packageOutputSelectors)
    canonicalizePackageOutputSelectors
    normalizePackageOutputSelectors
    ;

  fail = message:
    diagnostics.throw "value-type-mismatch" "abilities: ${message}";
  failLimit = message:
    diagnostics.throw "limit-exceeded" "abilities: ${message}";
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

  singletonSchemaDiscriminator = context: valueType: let
    values = valueType._abilitySchema.fields.schema.values or [];
  in
    if builtins.length values == 1
    then builtins.head values
    else fail "${context} must declare one exact schema discriminator";

  transitionFragment = fields: let
    checked =
      requireAttrs "transition fragment" [
        "operations"
        "decisions"
        "merges"
        "edges"
        "exports"
        "imports"
        "links"
        "handoffs"
        "provider_readiness"
        "obligations"
      ]
      fields;
  in {
    schema = "aos.ability.transition-fragment/v1";
    operations = checked.operations or [];
    decisions = checked.decisions or [];
    merges = checked.merges or [];
    edges = checked.edges or [];
    exports = checked.exports or [];
    imports = checked.imports or [];
    links = checked.links or [];
    handoffs = checked.handoffs or [];
    provider_readiness = checked.provider_readiness or [];
    obligations = checked.obligations or [];
  };

  identityKeyFor = domain: material:
    builtins.substring 7 64 (
      descriptorFor domain (normalizeSemanticValue material)
    );

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

  interfaceDocumentFromDeclaration = declaration: let
    configuration =
      if declaration.configurationType == null
      then {}
      else {
        configuration = normalizeConfigurationSchema declaration.configurationType;
      };
  in {
    schema = "aos.ability.interface/v1";
    required_features = uniqueSortedStrings "required features" declaration.requiredFeatures;
    interface =
      {
        inherit (declaration) description;
        name = requireQualifiedName "interface name" declaration.name;
        abi = requireU32Positive "interface ABI" declaration.abi;
        request = schemaFromType "interface request type" declaration.requestType;
        outputs =
          builtins.mapAttrs
          (name: normalizeOutput "interface output '${requireLocalKey "output name" name}'")
          declaration.outputs;
        methods = builtins.mapAttrs normalizeMethod declaration.methods;
        lifecycle = normalizeLifecycle declaration.lifecycle;
        guarantees = canonicalGuarantees "interface guarantees" declaration.guarantees;
        aggregation = normalizeAggregation declaration.aggregation;
      }
      // configuration;
  };

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
    normalized = builtins.tryEval (
      abilityTypes.normalize "instance identity" abilityTypes.instanceId value
    );
  in
    if normalized.success
    then normalized.value
    else let
      checked = requireMarker "instance identity" "aos-instance-id" value;
    in {
      environment = normalizeEnvironmentId checked.environment;
      inherit (checked) key;
    };

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
    else if builtins.elem schema.kind ["map" "optional" "refined"]
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

  packageForDeclarationAuthority = authority:
    if authority.kind == "package"
    then authority.package
    else null;
in rec {
  inherit
    schemas
    resourceControllerTransition
    declareInterface
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
    sourceStageFixedPoint
    packageAbilitiesFromProjection
    packageForDeclarationAuthority
    checkedProviderModuleEvaluation
    identityKeyFor
    singletonSchemaDiscriminator
    transitionFragment
    ;
  inherit
    (authenticatedPackageOutputs)
    authenticatedPackageOutputFor
    authenticatedPackageOutputsFor
    authenticatedPackageModuleRecordFor
    authenticatedPackageProjectionFor
    canonicalizeAuthenticatedPackages
    checkedAuthenticatedPackageProjection
    authenticatedProjectionOutputFor
    authenticatedModuleRecordIdentity
    canonicalizeAuthenticatedModuleRecords
    selectAuthenticatedPackageModuleRecords
    ;
  types = abilityTypes;
  interfaces = interfaceRegistry.readView;
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
        identityKeyFor
        interfaceIdentity
        normalizePackageOutputSelectors
        ;
      coreInterfaceModule = interfaceRegistry.module;
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
    request =
      if isLocalKey request || abilityTypes.declarationKey.check request
      then request
      else fail "result request must be a local or qualified declaration key";
    output = requireLocalKey "result output" output;
  };

  requestOutputIdentity = args: let
    checked = requireAttrs "request output identity" ["requests" "reference"] args;
    reference = checked.reference;
  in
    if
      !builtins.isAttrs reference
      || builtins.attrNames reference != ["_type" "output" "request"]
      || (reference._type or null) != "aos-request-output-reference"
      || !abilityTypes.declarationKey.check (reference.request or null)
      || !abilityTypes.localKey.check (reference.output or null)
    then throw "Request output identity requires one exact typed request-output reference."
    else let
      request =
        checked.requests.${reference.request}
        or (throw "Request output reference '${reference.request}' has no exact evaluated request declaration.");
    in
      if (request.authority or null) == null || (request.localKey or null) == null
      then throw "Request output reference '${reference.request}' has no retained declaration provenance."
      else {
        inherit (request) authority localKey;
        output = reference.output;
      };

  canonicalJsonOf = {
    type,
    value,
    maxBytes,
  }: let
    sourceSchema = abilityTypes.schemaOf "canonical-json source" type;
    effectResult =
      builtins.isAttrs value
      && builtins.attrNames value == ["_type" "key" "kind" "output" "up"]
      && value._type == "aos-effect-result-reference"
      && builtins.elem value.kind ["operation" "merge"]
      && builtins.isInt value.up
      && value.up >= 0
      && value.up <= 64
      && abilityTypes.localKey.check value.key
      && abilityTypes.localKey.check value.output;
    candidate = {
      _type = "aos-canonical-json";
      source_schema = sourceSchema;
      inherit value;
      max_bytes = maxBytes;
    };
  in
    if
      builtins.isInt maxBytes
      && maxBytes > 0
      && maxBytes <= maxStringLength
      && ((abilityTypes.deferredResult type).check value || effectResult)
    then candidate
    else fail "canonicalJsonOf requires a typed deferred value and a valid string byte limit";

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
  in "composition:requirement-${identityKeyFor "aos.ability.composition-requirement-key/v1" {
    implementation = requireDeclarationKey "composition implementation" checked.implementation;
    alias = requireLocalKey "composition requirement alias" checked.alias;
  }}";

  compositionRequestKey = args: let
    checked = requireAttrs "composition request identity" ["implementation" "providerInstance" "key"] args;
  in "composition:request-${identityKeyFor "aos.ability.composition-request-key/v1" {
    implementation = requireDeclarationKey "composition implementation" checked.implementation;
    provider_instance = requireDeclarationKey "composition provider instance" checked.providerInstance;
    key = requireLocalKey "composition request key" checked.key;
  }}";

  staticBinding = args: let
    checked = requireAttrs "static binding" ["request" "implementation" "providerInstance" "slot"] args;
    value = {
      request = requireDeclarationKey "static binding request" checked.request;
      implementation = requireDeclarationKey "static binding implementation" checked.implementation;
      providerInstance = requireDeclarationKey "static binding provider instance" checked.providerInstance;
      slot = requireLocalKey "static binding slot" checked.slot;
    };
  in {
    name = "source:binding-${identityKeyFor "aos.ability.static-binding-key/v1" value}";
    inherit value;
  };

  # Domain modules carry authenticated source provenance across a projection
  # into the shared graph. The graph option unwraps this before type checking.
  derivedDefinition = {
    provenance,
    value,
  }: {
    _type = "aos-derived-ability-definition";
    inherit provenance value;
  };

  packageOutput = args: let
    checked = requireAttrs "package output selector" ["package" "output"] args;
  in {
    _type = "aos-package-output-selector";
    package = requireLocalKey "package output package" (checked.package or "self");
    output = requireLocalKey "package output output" (checked.output or "out");
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
}
